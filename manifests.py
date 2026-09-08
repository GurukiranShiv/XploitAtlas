"""Owner-scoped inventory from explicitly supplied SBOMs and dependency manifests.

Inventories never become vulnerability evidence. Only OSV responses create matches.
Raw uploaded documents are not retained. Dependency locations are preserved as evidence.
"""
from __future__ import annotations
import hashlib
import json
import re
import threading
import time
import tomllib
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from core import now
from feeds import FeedError
from accounts import AccessError

MAX_COMPONENTS = 5000
MAX_DOCUMENT_BYTES = 5 * 1024 * 1024
MANIFESTS = {"package-lock.json", "npm-shrinkwrap.json", "requirements.txt", "poetry.lock", "Cargo.lock", "go.sum", "go.mod", "pom.xml", "bom.json", "sbom.json"}
ECOSYSTEMS = {"npm":"npm", "pypi":"PyPI", "maven":"Maven", "golang":"Go", "cargo":"crates.io", "nuget":"NuGet", "composer":"Packagist", "gem":"RubyGems"}
ADVISORY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}\Z")

def bounded_text(value, size):
    return value if isinstance(value, str) and len(value) <= size and not any(ord(c)<32 for c in value) else ""

def from_purl(purl, fallback_version=""):
    if not isinstance(purl, str) or not purl.startswith("pkg:") or len(purl)>1000:
        return None
    base = purl[4:].split("#",1)[0].split("?",1)[0]
    kind, sep, package = base.partition("/")
    if not sep or kind not in ECOSYSTEMS:
        return None
    # A PURL may omit its version when the SBOM component supplies it.
    # An unescaped npm @scope is not a version separator.
    if package.rfind("@") > package.rfind("/"):
        name, version = package.rsplit("@",1)
    else:
        name, version = package, fallback_version
    name, version = urllib.parse.unquote(name), urllib.parse.unquote(version)
    if kind == "maven":
        group, slash, artifact = name.rpartition("/")
        if not slash or not group or not artifact:
            return None
        name = group+":"+artifact
    return {"ecosystem":ECOSYSTEMS[kind], "name":name, "version":version}

def normalize_component(item):
    if not isinstance(item, dict):
        return None
    purl = bounded_text(item.get("purl"),1000)
    explicit_version = bounded_text(item.get("version"),100)
    parsed = from_purl(purl,explicit_version)
    data = parsed or item
    ecosystem = bounded_text(data.get("ecosystem"),40)
    name = bounded_text(data.get("name"),200)
    version = bounded_text(data.get("version"),100)
    if ecosystem == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    if not name:
        return None
    reason = bounded_text(item.get("skipReason"),240) or None
    if ecosystem not in ECOSYSTEMS.values():
        reason = "Unsupported or unspecified ecosystem; no identity guessed."
    elif not version or version in {"NOASSERTION", "NONE"} or any(c in version for c in "*^~<>=| ") or version.startswith(("file:","git", "http:","https:","workspace:","link:","npm:")):
        reason = "An exact resolved version is required."
    if purl and not parsed:
        reason = "Unsupported or incomplete package URL; no identity guessed."
    elif parsed and explicit_version and explicit_version != version:
        reason = "Conflicting component and package-URL versions; resolve the SBOM first."
        version = explicit_version
    return {"ecosystem":ecosystem, "name":name, "version":version, "purl":purl,
            "skipReason":reason, "locations": item.get("locations", [])[:50],
            "direct": item.get("direct") if isinstance(item.get("direct"), bool) else None,
            "scope": bounded_text(item.get("scope"),40) or "unknown",
            "evidence": bounded_text(item.get("evidence"),40) or "supplied"}

def deduplicate(items):
    result, seen = [], {}
    for item in items:
        component = normalize_component(item)
        if not component:
            raise ValueError("A component is missing a valid package name; no inventory was imported.")
        key = tuple(component[k] for k in ("ecosystem","name","version","purl"))
        if key not in seen:
            seen[key] = component; result.append(component)
        else:
            previous = seen[key]
            previous["locations"] = list(dict.fromkeys(previous["locations"] + component["locations"]))[:50]
            if component["direct"] is True:
                previous["direct"] = True
        if len(result)>MAX_COMPONENTS:
            raise ValueError("An inventory may contain at most 5,000 distinct components.")
    return result

def parse_sbom(document):
    if not isinstance(document, dict):
        raise ValueError("Upload a CycloneDX or SPDX JSON object.")
    entries = []
    if document.get("bomFormat") == "CycloneDX":
        if str(document.get("specVersion")) not in {"1.4","1.5","1.6"}:
            raise ValueError("Supported CycloneDX JSON versions: 1.4–1.6.")
        if not isinstance(document.get("components", []), list):
            raise ValueError("CycloneDX components must be an array.")
        queue = list(reversed(document.get("components", [])))
        visited = 0
        while queue:
            item = queue.pop(); visited += 1
            if visited > 20000 or not isinstance(item, dict):
                raise ValueError("Invalid or excessive SBOM components.")
            entries.append({"name":item.get("name"), "version":item.get("version"), "purl":item.get("purl"),
                            "locations":[item["bom-ref"]] if isinstance(item.get("bom-ref"),str) else [],
                            "scope":item.get("scope"),"evidence":"SBOM"})
            nested = item.get("components", [])
            if not isinstance(nested,list):
                raise ValueError("Nested components must be an array.")
            queue.extend(reversed(nested))
        kind = "CycloneDX " + str(document["specVersion"])
    elif document.get("spdxVersion") in {"SPDX-2.2", "SPDX-2.3"}:
        packages = document.get("packages", [])
        if not isinstance(packages,list) or len(packages)>20000:
            raise ValueError("Invalid or excessive SPDX packages.")
        for item in packages:
            if not isinstance(item,dict):
                raise ValueError("Invalid SPDX package.")
            refs = item.get("externalRefs", [])
            if not isinstance(refs,list):
                raise ValueError("Invalid SPDX external references.")
            purl = next((r.get("referenceLocator") for r in refs if isinstance(r,dict) and r.get("referenceType")=="purl"),None)
            entries.append({"name":item.get("name"), "version":item.get("versionInfo"), "purl":purl,
                            "locations":[item["SPDXID"]] if isinstance(item.get("SPDXID"),str) else [],"evidence":"SBOM"})
        kind = document["spdxVersion"]
    else:
        raise ValueError("Use CycloneDX JSON or SPDX 2.2/2.3 JSON. XML and archives are not accepted.")
    return deduplicate(entries), kind

def parse_manifest(filename, content):
    if filename not in MANIFESTS or not isinstance(content,str) or len(content.encode())>MAX_DOCUMENT_BYTES:
        raise ValueError("Unsupported or oversized manifest.")
    items = []
    if filename in {"package-lock.json", "npm-shrinkwrap.json"}:
        data = json.loads(content)
        if not isinstance(data,dict):
            raise ValueError("Invalid npm lockfile.")
        if isinstance(data.get("packages"),dict):
            for path, item in data["packages"].items():
                if not path or not isinstance(item,dict) or item.get("link"):
                    continue
                name = item.get("name") or path.rsplit("node_modules/",1)[-1]
                if "node_modules/" not in path and not item.get("name"):
                    continue
                items.append({"ecosystem":"npm", "name":name, "version":item.get("version")})
        else:
            dependencies = data.get("dependencies",{})
            if not isinstance(dependencies,dict):
                raise ValueError("npm dependencies must be an object.")
            queue = list(dependencies.items())
            visits = 0
            while queue:
                name,item = queue.pop(); visits += 1
                if visits>20000 or not isinstance(item,dict):
                    raise ValueError("Invalid or excessive npm dependency tree.")
                items.append({"ecosystem":"npm", "name":name, "version":item.get("version")})
                nested = item.get("dependencies",{})
                if not isinstance(nested,dict):
                    raise ValueError("npm dependencies must be an object.")
                queue.extend(nested.items())
    elif filename == "requirements.txt":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#","-")):
                continue
            # Never follow URLs, includes, indexes, or execute environment markers.
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*([A-Za-z0-9_.+!-]+)(?:\s*;.*)?(?:\s+#.*)?",line)
            if match:
                items.append({"ecosystem":"PyPI", "name":match[1], "version":match[2]})
            else:
                name = re.match(r"[A-Za-z0-9_.-]+",line)
                if name:
                    items.append({"ecosystem":"PyPI", "name":name[0], "version":""})
    elif filename in {"poetry.lock", "Cargo.lock"}:
        data = tomllib.loads(content)
        packages = data.get("package",[])
        if not isinstance(packages,list):
            raise ValueError("Lockfile packages must be an array.")
        for item in packages:
            if not isinstance(item,dict):
                raise ValueError("Invalid lockfile package.")
            ecosystem = "PyPI" if filename=="poetry.lock" else "crates.io"
            # Local/git packages may not correspond to the public registry identity.
            source = item.get("source")
            if filename=="Cargo.lock" and str(source or "") not in {"registry+https://github.com/rust-lang/crates.io-index","registry+sparse+https://index.crates.io/"}:
                ecosystem = ""
            if filename=="poetry.lock" and isinstance(source,dict) and source.get("type") in {"git","directory","file","url"}:
                ecosystem = ""
            items.append({"ecosystem":ecosystem,"name":item.get("name"),"version":item.get("version")})
    else:
        return parse_sbom(json.loads(content))[0]
    return deduplicate(items)

def make_purl(component):
    if component.get("purl"):
        purl = component["purl"]
        parsed = from_purl(purl)
        if parsed and not parsed["version"] and component.get("version"):
            base,mark,tail = purl.partition("?")
            base,fragment_mark,fragment = base.partition("#")
            return base+"@"+urllib.parse.quote(component["version"],safe="")+("?" +tail if mark else "")+("#"+fragment if fragment_mark else "")
        return purl
    reverse = {v:k for k,v in ECOSYSTEMS.items()}
    kind = reverse.get(component.get("ecosystem"))
    if not kind or not component.get("version"):
        return None
    name = component["name"].replace(":","/",1) if kind=="maven" else component["name"]
    return "pkg:"+kind+"/"+urllib.parse.quote(name,safe="/")+"@"+urllib.parse.quote(component["version"],safe="")

def cyclone_document(components):
    return {"bomFormat":"CycloneDX", "specVersion":"1.6", "version":1,
            "metadata":{"timestamp":now()}, "components":[
                {"type":"library","name":c["name"], **({"version":c["version"]} if c.get("version") else {}),
                 **({"purl":make_purl(c)} if make_purl(c) else {})} for c in components]}


def parse_document(filename, content):
    """Extract identities without running build tools, following URLs, or resolving ranges."""
    filename = str(filename).replace("\\", "/").rsplit("/", 1)[-1]
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise ValueError("Upload a UTF-8 manifest or SBOM of at most 5 MiB.")
    warnings, edges, root_purl = [], [], ""
    incomplete = False
    coverage = "resolved components in the supplied file"
    if filename in {"package-lock.json", "npm-shrinkwrap.json"}:
        document = json.loads(content)
        components = parse_manifest(filename, content)
        kind = "npm lockfile"
        paths = document.get("packages", {})
        if isinstance(paths, dict) and paths:
            root_deps = set((paths.get("", {}).get("dependencies") or {}).keys())
            root_deps.update((paths.get("", {}).get("devDependencies") or {}).keys())
            mapped = {}
            entries = []
            for location, package in paths.items():
                if not location or not isinstance(package, dict):
                    continue
                name = package.get("name") or location.rsplit("node_modules/", 1)[-1]
                if "node_modules/" not in location and not package.get("name"):
                    continue
                item = {"ecosystem": "npm", "name": name, "version": package.get("version", ""),
                        "locations": [location], "direct": location == "node_modules/" + name and name in root_deps,
                        "scope": "development" if package.get("dev") else "runtime", "evidence": "lockfile"}
                if package.get("link") or str(package.get("resolved", "")).startswith(("git", "file:", "link:")):
                    item["skipReason"] = "Local or Git dependency: supply an SBOM with its resolved registry identity."
                entries.append(item)
                mapped[location] = item
            for location, package in paths.items():
                if not isinstance(package, dict):
                    continue
                for dependency in (package.get("dependencies") or {}):
                    parent = location
                    candidates = []
                    while parent:
                        candidates.append(parent + "/node_modules/" + dependency)
                        parent = parent.rsplit("/node_modules/", 1)[0] if "/node_modules/" in parent else ""
                    candidates.append("node_modules/" + dependency)
                    target = next((p for p in candidates if p in mapped), None)
                    if target:
                        edges.append({"from": location or "root", "to": target, "kind": "depends_on"})
            components = deduplicate(entries)
    elif filename == "go.sum":
        entries = []
        for line in content.splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) != 3 or not parts[2].startswith("h1:"):
                raise ValueError("Invalid go.sum line.")
            version = parts[1]
            item = {"ecosystem": "Go", "name": parts[0], "version": version.removesuffix("/go.mod"),
                    "evidence": "checksum", "locations": [filename]}
            if version.endswith("/go.mod"):
                item["skipReason"] = "Only a go.mod checksum is recorded; this is not evidence the module was selected."
            entries.append(item)
        full_checksums = {(item["name"],item["version"]) for item in entries if not item.get("skipReason")}
        entries = [item for item in entries if not item.get("skipReason") or (item["name"],item["version"]) not in full_checksums]
        components, kind, incomplete = deduplicate(entries), "Go checksums", True
        coverage = "checksum candidates; not the selected build list"
        warnings.append("go.sum can retain unused versions. Import a resolved Go SBOM to verify build applicability.")
    elif filename == "go.mod":
        incomplete = True
        entries, in_block = [], False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_block = True; continue
            if in_block and line == ")":
                in_block = False; continue
            match = re.match(r"(?:require\s+)?([^\s]+)\s+(v[^\s]+)", line) if in_block or line.startswith("require ") else None
            if match:
                entries.append({"ecosystem":"Go", "name":match[1], "version":match[2],
                                "direct":"// indirect" not in line, "evidence":"declared"})
            if line.startswith(("replace ", "exclude ")):
                warnings.append("Go replace/exclude directives need a resolved SBOM.")
                incomplete = True
        components, kind = deduplicate(entries), "Go module declarations"
        coverage = "declared requirements; transitive resolution not performed"
    elif filename == "pom.xml":
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", content, re.I):
            raise ValueError("XML document types and entity declarations are not accepted.")
        root = ET.fromstring(content)
        if len(list(root.iter())) > 40000:
            raise ValueError("POM exceeds the element limit.")
        for element in root.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]
        properties = {p.tag: (p.text or "").strip() for p in root.findall("./properties/*")}
        for key in ("version", "groupId", "artifactId"):
            properties["project." + key] = root.findtext(key) or root.findtext("parent/" + key) or ""
            properties["pom." + key] = properties["project." + key]
        def resolved(value):
            for _ in range(8):
                updated = re.sub(r"\$\{([^}]+)\}", lambda m: properties.get(m[1], m[0]), value or "")
                if updated == value:
                    break
                value = updated
            return (value or "").strip()
        managed = {}
        for dep in root.findall("./dependencyManagement/dependencies/dependency"):
            managed[(resolved(dep.findtext("groupId")), resolved(dep.findtext("artifactId")))] = resolved(dep.findtext("version"))
        entries = []
        for dep in root.findall("./dependencies/dependency"):
            group, artifact = resolved(dep.findtext("groupId")), resolved(dep.findtext("artifactId"))
            version = resolved(dep.findtext("version")) or managed.get((group, artifact), "")
            entry = {"ecosystem":"Maven", "name":group + ":" + artifact, "version":version,
                     "direct":True, "scope":dep.findtext("scope") or "compile", "evidence":"declared"}
            if not group or not artifact or "${" in group + artifact + version or any(c in version for c in "[](),"):
                entry["skipReason"] = "Maven property, parent, or version range needs dependency resolution."
            entries.append(entry)
        components, kind, incomplete = deduplicate(entries), "Maven POM", True
        coverage = "direct declarations; profiles, parents and transitive dependencies require resolution"
        warnings.append("POM imports check direct pinned dependencies. Use a resolved CycloneDX SBOM for complete build coverage.")
    elif filename == "requirements.txt":
        components, kind = parse_manifest(filename, content), "Python requirements"
        coverage = "exact pins in the supplied requirements file"
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r", "--requirement", "-c", "--constraint", "-e", "--editable")):
                warnings.append("Included files, constraints and editable dependencies are not followed; upload resolved pins.")
                incomplete = True
            if line.startswith(("-i","--index-url","--extra-index-url","--find-links","-f")):
                warnings.append("Custom package sources need an SBOM with verified registry identities.")
                incomplete = True
                for component in components:
                    component["skipReason"] = "Custom package source: public PyPI identity is unverified."
            if ";" in line:
                warnings.append("Conditional requirements are checked conservatively; environment markers are not evaluated.")
        warnings = list(dict.fromkeys(warnings))
    elif filename in {"Cargo.lock", "poetry.lock"}:
        components, kind = parse_manifest(filename, content), "Cargo lockfile" if filename == "Cargo.lock" else "Poetry lockfile"
    else:
        components, kind = parse_sbom(json.loads(content))
        document = json.loads(content)
        if document.get("bomFormat") == "CycloneDX":
            root_purl = str(document.get("metadata",{}).get("component",{}).get("purl") or "")[:1000]
            for dependency in document.get("dependencies", []):
                if isinstance(dependency, dict):
                    edges.extend({"from":str(dependency.get("ref", ""))[:1000], "to":str(target)[:1000],
                                  "kind":"depends_on"} for target in dependency.get("dependsOn", [])[:5000])
    if not components:
        raise ValueError("No package identities were found in this document.")
    skipped = sum(bool(c["skipReason"]) for c in components)
    if skipped:
        warnings.append(f"{skipped} components need a supported ecosystem and exact registry version.")
    return {"components": components, "kind": kind, "warnings": warnings, "dependencyEdges": edges[:20000],
            "coverage": coverage, "complete": not (incomplete or skipped), "rootPurl":root_purl,
            "fingerprint": hashlib.sha256(content.encode("utf-8")).hexdigest()}
