import subprocess
import os
import re
from elftools.elf.elffile import ELFFile
from BaseAnalysis import BaseAnalysis
from version_db import (
    QUANTUM_VULNERABLE, HYBRID, PQC_READY, NO_CRYPTO_DEP,
    PQC_LIBRARY_DB, SO_TO_LIBRARY_MAP
)


class FileDependencyAnalysis(BaseAnalysis):
    def __init__(self, scan_folder, crypto_lib_desc, verbose=0):
        super().__init__(scan_folder, crypto_lib_desc, verbose)

        self.sw_dep = {}
        self.vuln_elf = []

        self.dep_graph = {}

        self._ldconfig_cache = self._build_ldconfig_cache()

    def _build_ldconfig_cache(self):
        # Run ldconfig -p once and cache as {lib_name: full_path}
        cache = {}
        try:
            result = subprocess.run(['ldconfig', '-p'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in result.stdout.splitlines():
                if '=>' not in line:
                    continue
                parts = line.strip().split('=>')
                if len(parts) != 2:
                    continue
                lib_name = parts[0].strip().split()[0]
                lib_path = parts[1].strip()
                cache[lib_name] = lib_path
        except Exception:
            pass
        return cache

    def _get_needed_libs(self, fpath):
        # Extract DT_NEEDED entries from ELF .dynamic section using pyelftools
        needed = []
        try:
            with open(fpath, 'rb') as f:
                elf = ELFFile(f)
                dynamic = elf.get_section_by_name('.dynamic')
                if dynamic is None:
                    return needed
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        needed.append(tag.needed)
        except Exception:
            pass
        return needed

    def _resolve_lib_path(self, lib_name):
        # Resolve library name to full path via ldconfig cache then fallback
        if lib_name in self._ldconfig_cache:
            return self._ldconfig_cache[lib_name]
        std_dirs = [
            '/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu',
            '/lib/i386-linux-gnu',   '/usr/lib/i386-linux-gnu',
            '/lib', '/usr/lib',
        ]
        for d in std_dirs:
            candidate = os.path.join(d, lib_name)
            if os.path.exists(candidate):
                return candidate
        return None

    def _extract_version(self, lib_path):
        """
        Extract version tuple (major, minor, patch) from crypto library.
        Strategy 1: parse version from realpath soname
        Strategy 2: parse version string from ELF .comment section
        Returns tuple e.g. (1, 1, 1) or None if not found.
        """
        if lib_path is None:
            return None

        # Strategy 0: search for known library version strings in .comment and .rodata
        # Scanning both sections here avoids matching compiler versions (e.g. GCC 13.3.0)
        # and ensures OpenSSL/wolfSSL version strings are found before soname parsing.
        LIB_VERSION_PATTERNS = [
            r'wolfSSL[_ ]v?(\d+)\.(\d+)\.(\d+)',
            r'OpenSSL[_ ](\d+)\.(\d+)\.(\d+)[a-z]?',
            r'mbedTLS[_ ](\d+)\.(\d+)\.(\d+)',
            r'Botan[_ ](\d+)\.(\d+)\.(\d+)',
        ]
        try:
            with open(lib_path, 'rb') as f:
                elf = ELFFile(f)
                for section_name in ['.comment', '.rodata', '.data.rel.ro']:
                    sec = elf.get_section_by_name(section_name)
                    if not sec:
                        continue
                    text = sec.data().decode('utf-8', errors='ignore')
                    for pattern in LIB_VERSION_PATTERNS:
                        m = re.search(pattern, text)
                        if m:
                            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except Exception:
            pass

        # Strategy 1: parse version from realpath soname
        # Handle both "libcrypto.so.1.1.1" and "libcrypto.so.3" (single version number)
        # Skip for wolfSSL: soname version is ABI version, not library version
        try:
            real = os.path.realpath(lib_path)
            soname = os.path.basename(real)
            if 'wolfssl' not in soname.lower():
                # Try full version first (e.g. 1.1.1)
                m = re.search(r'\.so\.(\d+)\.(\d+)\.?(\d*)', soname)
                if m:
                    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
                # Fallback: single version number (e.g. libcrypto.so.3 → 3.0.0)
                m = re.search(r'\.so\.(\d+)$', soname)
                if m:
                    return (int(m.group(1)), 0, 0)
        except Exception:
            pass

        # Strategy 3: wolfSSL fallback — plain version string (e.g. "5.7.2") in .rodata
        # wolfSSL embeds version without library prefix between null bytes
        try:
            so_basename = os.path.basename(lib_path)
            if 'wolfssl' in so_basename.lower():
                with open(lib_path, 'rb') as f:
                    elf = ELFFile(f)
                    for section_name in ['.rodata', '.data.rel.ro']:
                        sec = elf.get_section_by_name(section_name)
                        if not sec:
                            continue
                        text = sec.data().decode('utf-8', errors='ignore')
                        for m in re.finditer(r'(\d+)\.(\d+)\.(\d+)', text):
                            major = int(m.group(1))
                            minor = int(m.group(2))
                            # Reject compiler versions: wolfSSL major is always < 20
                            if major < 20:
                                return (major, minor, int(m.group(3)))
        except Exception:
            pass

        return None

    def _judge_posture(self, lib_key, version):
        """
        Look up PQC_LIBRARY_DB and return (posture, is_research_grade).
        Falls back to QUANTUM_VULNERABLE if version or key is unknown.
        """
        entry = PQC_LIBRARY_DB.get(lib_key)
        if entry is None:
            return QUANTUM_VULNERABLE, False

        is_research = entry.get('is_research_grade', False)

        # Version-agnostic default posture (e.g. BoringSSL, liboqs)
        if entry['default_posture'] is not None:
            return entry['default_posture'], is_research

        if version is None:
            return QUANTUM_VULNERABLE, is_research

        pqc_ready_from     = entry.get('pqc_ready_from')
        transitioning_from = entry.get('transitioning_from')
        vulnerable_below   = entry.get('vulnerable_below')

        if pqc_ready_from and version >= pqc_ready_from:
            return PQC_READY, is_research
        if transitioning_from and version >= transitioning_from:
            return HYBRID, is_research
        if vulnerable_below and version < vulnerable_below:
            return QUANTUM_VULNERABLE, is_research

        return QUANTUM_VULNERABLE, is_research

    def _find_crypto_lib_for_elf(self, elf):
        # BFS from each crypto lib through dep_graph to find which one reaches elf.
        # dep_graph maps lib -> [dependents], so we traverse forward from each crypto lib.
        for libpath in self.crypto_lib.keys():
            if libpath not in self.dep_graph:
                continue
            visited = set()
            queue = [libpath]
            while queue:
                node = queue.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                if node == elf:
                    return libpath
                for child in self.dep_graph.get(node, []):
                    if child not in visited:
                        queue.append(child)
        return None

    def _resolve_lib_key(self, so_name):
        # Look up SO_TO_LIBRARY_MAP, fallback to prefix matching
        lib_key = SO_TO_LIBRARY_MAP.get(so_name)
        if lib_key is None:
            for known_so, key in SO_TO_LIBRARY_MAP.items():
                if so_name.startswith(known_so.split('.so')[0]):
                    lib_key = key
                    break
        return lib_key

    def gen_report(self, output_folder=None):

        self.analyze()

        report = list()

        # Report crypto lib root entries with their actual posture
        for libpath, _ in self.crypto_lib.items():
            so_name = os.path.basename(libpath)
            lib_key = self._resolve_lib_key(so_name)
            version = self._extract_version(libpath)
            posture, is_research = self._judge_posture(lib_key, version)
            version_list = list(version) if version else None
            report.append({
                "elf": libpath,
                "path": [libpath],
                "type": self._file_type(libpath),
                "posture": posture,
                "version": version_list,
                "is_research_grade": is_research,
            })

        # Report each QV app once, linked to its closest crypto lib
        for elf in self.elf_files:
            if elf not in self.vuln_elf:
                report.append({
                    "elf": elf,
                    "path": [elf],
                    "type": self._file_type(elf),
                    "posture": NO_CRYPTO_DEP,
                    "version": None,
                    "is_research_grade": False,
                })
                continue

            # Find the crypto lib this elf depends on (directly or indirectly)
            # First try direct lookup, then BFS through dep_graph
            matched_libpath = None
            for libpath in self.crypto_lib.keys():
                if libpath in self.dep_graph and elf in self.dep_graph.get(libpath, []):
                    matched_libpath = libpath
                    break
            if matched_libpath is None:
                matched_libpath = self._find_crypto_lib_for_elf(elf)

            if matched_libpath is None:
                continue

            so_name = os.path.basename(matched_libpath)
            lib_key = self._resolve_lib_key(so_name)
            version = self._extract_version(matched_libpath)
            posture, is_research = self._judge_posture(lib_key, version)
            version_list = list(version) if version else None

            report.append({
                "elf": elf,
                "path": [elf, matched_libpath],
                "type": self._file_type(elf),
                "posture": posture,
                "version": version_list,
                "is_research_grade": is_research,
            })

        qv_apps = [x for x in (set(self.dep_graph.keys()) & set(self.elf_files))]
        full_report = {
            "metadata": {
                "num_apps_before": len(self.elf_files),
                "num_apps_after": len(qv_apps),
            },
            "QV_apps": qv_apps,
            "report": report,
        }

        if output_folder is not None:
            self.write_report(full_report, "result.json", output_folder)

        return full_report

    def analyze(self):
        self._get_all_elf()
        self._gen_sw_dep_graph()

        # Remove isolated nodes (nodes with no edges)
        connected = set()
        for node, children in self.sw_dep.items():
            if children:
                connected.add(node)
                connected.update(children)
        self.sw_dep = {k: v for k, v in self.sw_dep.items() if k in connected}

        descendants = self._get_nodes_from_crypto_lib(self.sw_dep)

        self.vuln_elf = list(descendants)
        self.dep_graph = {k: v for k, v in self.sw_dep.items() if k in descendants}

    def _get_nodes_from_crypto_lib(self, graph):
        # BFS/DFS to find all nodes reachable from identified crypto lib nodes
        descendants = set()
        for node in self.crypto_lib.keys():
            if node not in graph:
                continue
            # BFS from crypto lib node through the adjacency dict
            queue = [node]
            visited = {node}
            while queue:
                current = queue.pop(0)
                descendants.add(current)
                for child in graph.get(current, []):
                    if child not in visited:
                        visited.add(child)
                        queue.append(child)
            descendants |= visited
        return descendants

    def _gen_sw_dep_graph(self):
        self.checked = set()
        for elf in self.elf_files:
            self._gen_sw_dep_graph_helper(elf, elf, 0, 5)

    def _gen_sw_dep_graph_helper(self, root, elf, cur_depth=0, max_depth=5):
        if cur_depth >= max_depth:
            return

        # Already checked, skip
        if elf in self.checked:
            return

        self.checked.add(elf)
        self.sw_dep.setdefault(elf, [])

        lib = self._is_crypto_lib(elf)
        if lib is not None:
            self.crypto_lib[elf] = lib

        # Recursively check dynamic library dependencies
        shared_lib_paths = self._list_direct_dep(elf)
        if shared_lib_paths is not None:
            for p in shared_lib_paths:
                self.sw_dep.setdefault(p, [])
                self.sw_dep[p].append(elf)  # Library points to main exec
                self._gen_sw_dep_graph_helper(root, p, cur_depth + 1, max_depth)

    # Find whether elf corresponds to crypto lib; if so, which one.
    def _is_crypto_lib(self, elf):
        syms = self.get_api_exposed(elf)
        if syms is None:
            return None
        elf_name = os.path.basename(elf)
        for lib in self.crypto_lib_desc:
            if lib['regex'].match(elf_name):
                num_intersec = len(set(lib['APIs']) & set(syms))
                num_total = len(set(lib['APIs']))
                if num_intersec / num_total > .8:
                    return lib
        return None

    def _get_all_elf(self):

        for root, _, files in os.walk(self.scan_folder):
            for file in files:
                file_path = os.path.join(root, file)
                if self._is_elf(file_path):
                    self.elf_files.append(os.path.join(root, file))

        if self.verbose:
            print("Folder:", self.scan_folder, "; # elf files:", len(self.elf_files))

    def _list_direct_dep(self, executable_path):
        # Get direct dependency paths using pyelftools DT_NEEDED (level 1)
        needed = self._get_needed_libs(executable_path)
        if not needed:
            return None
        paths = []
        for lib_name in needed:
            path = self._resolve_lib_path(lib_name)
            if path:
                paths.append(path)
        return paths if paths else None
