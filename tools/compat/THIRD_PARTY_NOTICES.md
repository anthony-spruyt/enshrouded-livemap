# Third-party notices of the compat tool

The Linux `livemap_compat` binary published with each release is statically linked. This file lists the libraries it
contains and the terms they come with. The DLL has its own notices in the `THIRD_PARTY_NOTICES.md` at the repository root.

## Zydis (<https://github.com/zyantific/zydis>)

```text
The MIT License (MIT)

Copyright (c) 2014-2024 Florian Bernd
Copyright (c) 2014-2024 Joel Höner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```

## Zycore (<https://github.com/zyantific/zycore-c>)

```text
The MIT License (MIT)

Copyright (c) 2018-2024 Florian Bernd
Copyright (c) 2018-2024 Joel Höner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```

## GNU C Library (<https://sourceware.org/glibc/>)

The binary contains the GNU C Library, licensed under the GNU Lesser General Public License, version 2.1 (the text is at
<https://spdx.org/licenses/LGPL-2.1-only.html>).

- Source: the `glibc` source package of the Ubuntu release the build runs on (`apt source glibc`), and
  the upstream project named above.
- Relinking: the complete source of the tool is in this repository under `tools/compat`. Building it as described in
  `tools/compat/README.md` against a modified C library produces a binary that uses that library.

## GCC runtime libraries (<https://gcc.gnu.org/>)

The binary contains `libstdc++` and `libgcc`, licensed under the GNU General Public License, version 3 with the GCC
Runtime Library Exception, version 3.1 (<https://spdx.org/licenses/GCC-exception-3.1.html>). The exception lets a
program that uses these libraries be distributed under terms of its own choosing. The source is the `gcc` source package
of the same Ubuntu release (`apt source gcc`) and <https://gcc.gnu.org/>.
