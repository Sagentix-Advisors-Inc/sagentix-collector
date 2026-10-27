# Third-party notices

The collector runs these programs as separate processes, or reads their output. It does not copy their source code. The runner image (`runner/Dockerfile`) installs most of them from their publishers' package registries (PyPI, Cinc's package server) or from the release assets each project publishes on GitHub, and checks every downloaded release asset against the SHA-256 its publisher lists; the MITRE STIG profiles, whose publisher lists none, are checked against the SHA-256 of the tagged tarball pinned when they were added. Five Go programs (Trivy, Gitleaks, OpenSSF Scorecard, Open Policy Agent and Kubescape) it builds from source instead, at the tag and commit each entry names, raising only the Go modules listed in `runner/go-module-fixes.txt`; their own source code is unchanged, but their `go.mod` and `go.sum` files are not. The Kubescape regolibrary entry describes the one other change, to an input file. sos-app's check catalogues name their checks and titles, taken from each program's own metadata at a pinned version. Each name below is used only to say where a check comes from; none of these projects endorses Sagentix.

## Prowler

- Project: https://github.com/prowler-cloud/prowler
- Version: 5.45.0 (git tag `5.45.0`, commit bffc8844c1c9a3666e37a2ada4ee05f62e1446b0; PyPI `prowler==5.45.0`)
- Licence: Apache License 2.0
- Copyright: Copyright @ 2024 Toni de la Fuente (as stated in Prowler's LICENSE file)
- Used for: the `prowler` source (`src/sources/prowler.ts`) runs the `prowler` command or reads its OCSF output. `apps/sos-app/src/data/checks/prowler_<provider>.json` holds Prowler check ids, check titles (`CheckTitle`), severities and the FedRAMP 20x KSI and NIST SP 800-53 mappings, all read from that release by `apps/sos-app/scripts/build_prowler_catalog.py`.
- Changes: none to Prowler. sos-app keeps only the checks it can map, takes hub controls only from Prowler's own SP 800-53 Rev. 5 mapping (a check without one counts toward its KSIs only, since 2026-10-15), and checks Prowler's KSI tags against the official lists. Those are Sagentix's derivations, not Prowler's.
- Texts copied: `apps/sos-app/src/data/guidance/prowler_remediation_<provider>.json` holds, for each check in that provider's catalogue, Prowler's own `Risk` and `Remediation` texts (`Recommendation.Text` and `Url`, and `Code.CLI`, `Terraform`, `NativeIaC`, `Other`) from the same release, written by the same script. They are Prowler's work under the Apache License 2.0, shipped unmodified with this attribution and a `notice` line in each file; empty fields become null and each field is cut at 4,000 characters. sos-app shows them in its per-control guides.
- Prowler ships no NOTICE file at this tag.

The licence text, as distributed with Prowler 5.45.0:

```text
                                Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright @ 2024 Toni de la Fuente

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

## Go

- Project: https://go.dev (source https://github.com/golang/go)
- Version: 1.27.3 (git tag `go1.27.3`, commit 2aae1000ea1d4b28923b96db28acf4e3b99d6aff)
- Licence: BSD 3-Clause License
- Copyright: Copyright 2009 The Go Authors.
- Used for: compiling Trivy, Gitleaks, OpenSSF Scorecard, OPA and Kubescape in the runner image's build stage. The toolchain is not in the image; its runtime and standard library are inside each of those five binaries.
- Downloaded from: https://go.dev/dl/go1.27.3.linux-amd64.tar.gz (SHA-256 65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40) and go1.27.3.linux-arm64.tar.gz (SHA-256 a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49), as listed at https://go.dev/dl/?mode=json
- Changes: none

The licence text, as distributed with Go 1.27.3:

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Trivy

- Project: https://github.com/aquasecurity/trivy
- Version: 0.75.0 (git tag `v0.75.0`, commit 591e9799316a602e703f0b484f6c6d7b234ec8f3)
- Licence: Apache License 2.0
- Copyright: Copyright 2019-2020 Aqua Security Software Ltd. (as stated in Trivy's NOTICE file; the LICENSE appendix keeps the template line `Copyright [yyyy] [name of copyright owner]`)
- Used for: the runner image bundles `trivy` so a job can write the JSON report (`--format json`) that the `trivy` source (`src/sources/trivy.ts`) reads. `apps/sos-app/src/data/checks/trivy.json` names the checks.
- Built from source: the runner image fetches the tag `v0.75.0` (commit 591e9799316a602e703f0b484f6c6d7b234ec8f3) and compiles it with Go 1.27.3 (see Go below), raising modules to the floors in `collector/runner/go-module-fixes.txt`. Changes: none to the project's own source; `go.mod` and `go.sum` move only where a floor applies.

The licence terms (sections 1 to 9 and the end of terms) are identical, word for word, to the Apache License 2.0 text reproduced under Prowler above; the file at `v0.75.0` differs only in its appendix template. Trivy ships this NOTICE file at the tag, reproduced as distributed:

```text
Trivy
Copyright 2019-2020 Aqua Security Software Ltd. 

This product includes software developed by Aqua Security (https://aquasec.com).
```

## Gitleaks

- Project: https://github.com/gitleaks/gitleaks
- Version: 8.30.1 (git tag `v8.30.1`, commit 83d9cd684c87d95d656c1458ef04895a7f1cbd8e)
- Licence: MIT License
- Copyright: Copyright (c) 2019 Zachary Rice (as stated in Gitleaks' LICENSE file)
- Used for: the runner image bundles `gitleaks` so a job can write the JSON report (`--report-format json`) that the `gitleaks` source (`src/sources/gitleaks.ts`) reads.
- Built from source: the runner image fetches the tag `v8.30.1` (commit 83d9cd684c87d95d656c1458ef04895a7f1cbd8e) and compiles it with Go 1.27.3 (see Go below), raising modules to the floors in `collector/runner/go-module-fixes.txt`. Changes: none to the project's own source; `go.mod` and `go.sum` move only where a floor applies.

The licence text, as distributed with Gitleaks 8.30.1:

```text
MIT License

Copyright (c) 2019 Zachary Rice

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

## OpenSSF Scorecard

- Project: https://github.com/ossf/scorecard
- Version: 5.6.0 (git tag `v5.6.0`, commit 61e84743356275f6ffca23b1b2f2cb945e19eb96)
- Licence: Apache License 2.0
- Copyright: Copyright 2020 OpenSSF Scorecard Authors (as stated in Scorecard's LICENSE file)
- Used for: the runner image bundles `scorecard` so a job can write the JSON result (`--format=json`) that the `scorecard` source (`src/sources/scorecard.ts`) reads.
- Built from source: the runner image fetches the tag `v5.6.0` (commit 61e84743356275f6ffca23b1b2f2cb945e19eb96) and compiles it with Go 1.27.3 (see Go below), raising modules to the floors in `collector/runner/go-module-fixes.txt`. Changes: none to the project's own source; `go.mod` and `go.sum` move only where a floor applies.
- Scorecard ships no NOTICE file at this tag.

The licence terms (sections 1 to 9 and the end of terms) are identical, word for word, to the Apache License 2.0 text reproduced under Prowler above; the file at `v5.6.0` differs only in its appendix, which carries the copyright line above.

## Open Policy Agent (OPA)

- Project: https://github.com/open-policy-agent/opa
- Version: 1.21.1 (git tag `v1.21.1`, commit 2a109e54103370d2ef288782ef3cb4c8a37902b2)
- Licence: Apache License 2.0
- Copyright: none stated; the LICENSE appendix keeps the template line `Copyright {yyyy} {name of copyright owner}`
- Used for: ScubaGoggles evaluates its Rego baselines with the bundled `opa`, and the `cloudflare` source (`src/sources/cloudflare/opa.ts`) runs `opa eval` over `iac/policy/cloudflare` when given `--tofu-state`.
- Built from source: the runner image fetches the tag `v1.21.1` (commit 2a109e54103370d2ef288782ef3cb4c8a37902b2) and compiles it with Go 1.27.3 (see Go below), raising modules to the floors in `collector/runner/go-module-fixes.txt`. Changes: none to the project's own source; `go.mod` and `go.sum` move only where a floor applies.
- OPA ships no NOTICE file at this tag.

The licence terms (sections 1 to 9 and the end of terms) are identical, word for word, to the Apache License 2.0 text reproduced under Prowler above; the file at `v1.21.1` differs only in its appendix template.

## ScubaGoggles

- Project: https://github.com/cisagov/ScubaGoggles (Cybersecurity and Infrastructure Security Agency)
- Version: 1.0.1 (git tag `v1.0.1`, commit 8370434288a1a9c114ffbddf57182ba8d990fb1a; PyPI `scubagoggles==1.0.1`)
- Licence: Creative Commons Zero v1.0 Universal (CC0 1.0)
- Copyright: none claimed; the README says the project is distributed under the Creative Commons Zero licence "unless otherwise noted"
- Used for: the runner image installs ScubaGoggles in `/opt/scubagoggles` so a job can write the ScubaResults JSON that the `scubagoggles` source (`src/sources/scuba.ts`) reads. `apps/sos-app/src/data/checks/scubagoggles.json` holds its policy ids and CISA's SP 800-53 mapping, read from the same tag by `apps/sos-app/scripts/build_scuba_catalog.py`.
- Downloaded from: https://files.pythonhosted.org/packages/6e/23/9cacc45e30c1253e235f372468505330aaef16c0cc5d1559b0d34e5606c2/scubagoggles-1.0.1-py3-none-any.whl (SHA-256 0fcbbc73f2c646fb6b01ec8a1a068954684a6022d0a7a32b3b21bba9f408bdc9, the digest PyPI lists for that file). Its Python dependencies come from PyPI at install time, unpinned, as Prowler's do.
- Changes: none

The licence text, as distributed with ScubaGoggles 1.0.1:

```text
Creative Commons Legal Code

CC0 1.0 Universal

    CREATIVE COMMONS CORPORATION IS NOT A LAW FIRM AND DOES NOT PROVIDE
    LEGAL SERVICES. DISTRIBUTION OF THIS DOCUMENT DOES NOT CREATE AN
    ATTORNEY-CLIENT RELATIONSHIP. CREATIVE COMMONS PROVIDES THIS
    INFORMATION ON AN "AS-IS" BASIS. CREATIVE COMMONS MAKES NO WARRANTIES
    REGARDING THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS
    PROVIDED HEREUNDER, AND DISCLAIMS LIABILITY FOR DAMAGES RESULTING FROM
    THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS PROVIDED
    HEREUNDER.

Statement of Purpose

The laws of most jurisdictions throughout the world automatically confer
exclusive Copyright and Related Rights (defined below) upon the creator
and subsequent owner(s) (each and all, an "owner") of an original work of
authorship and/or a database (each, a "Work").

Certain owners wish to permanently relinquish those rights to a Work for
the purpose of contributing to a commons of creative, cultural and
scientific works ("Commons") that the public can reliably and without fear
of later claims of infringement build upon, modify, incorporate in other
works, reuse and redistribute as freely as possible in any form whatsoever
and for any purposes, including without limitation commercial purposes.
These owners may contribute to the Commons to promote the ideal of a free
culture and the further production of creative, cultural and scientific
works, or to gain reputation or greater distribution for their Work in
part through the use and efforts of others.

For these and/or other purposes and motivations, and without any
expectation of additional consideration or compensation, the person
associating CC0 with a Work (the "Affirmer"), to the extent that he or she
is an owner of Copyright and Related Rights in the Work, voluntarily
elects to apply CC0 to the Work and publicly distribute the Work under its
terms, with knowledge of his or her Copyright and Related Rights in the
Work and the meaning and intended legal effect of CC0 on those rights.

1. Copyright and Related Rights. A Work made available under CC0 may be
protected by copyright and related or neighboring rights ("Copyright and
Related Rights"). Copyright and Related Rights include, but are not
limited to, the following:

  i. the right to reproduce, adapt, distribute, perform, display,
     communicate, and translate a Work;
 ii. moral rights retained by the original author(s) and/or performer(s);
iii. publicity and privacy rights pertaining to a person's image or
     likeness depicted in a Work;
 iv. rights protecting against unfair competition in regards to a Work,
     subject to the limitations in paragraph 4(a), below;
  v. rights protecting the extraction, dissemination, use and reuse of data
     in a Work;
 vi. database rights (such as those arising under Directive 96/9/EC of the
     European Parliament and of the Council of 11 March 1996 on the legal
     protection of databases, and under any national implementation
     thereof, including any amended or successor version of such
     directive); and
vii. other similar, equivalent or corresponding rights throughout the
     world based on applicable law or treaty, and any national
     implementations thereof.

2. Waiver. To the greatest extent permitted by, but not in contravention
of, applicable law, Affirmer hereby overtly, fully, permanently,
irrevocably and unconditionally waives, abandons, and surrenders all of
Affirmer's Copyright and Related Rights and associated claims and causes
of action, whether now known or unknown (including existing as well as
future claims and causes of action), in the Work (i) in all territories
worldwide, (ii) for the maximum duration provided by applicable law or
treaty (including future time extensions), (iii) in any current or future
medium and for any number of copies, and (iv) for any purpose whatsoever,
including without limitation commercial, advertising or promotional
purposes (the "Waiver"). Affirmer makes the Waiver for the benefit of each
member of the public at large and to the detriment of Affirmer's heirs and
successors, fully intending that such Waiver shall not be subject to
revocation, rescission, cancellation, termination, or any other legal or
equitable action to disrupt the quiet enjoyment of the Work by the public
as contemplated by Affirmer's express Statement of Purpose.

3. Public License Fallback. Should any part of the Waiver for any reason
be judged legally invalid or ineffective under applicable law, then the
Waiver shall be preserved to the maximum extent permitted taking into
account Affirmer's express Statement of Purpose. In addition, to the
extent the Waiver is so judged Affirmer hereby grants to each affected
person a royalty-free, non transferable, non sublicensable, non exclusive,
irrevocable and unconditional license to exercise Affirmer's Copyright and
Related Rights in the Work (i) in all territories worldwide, (ii) for the
maximum duration provided by applicable law or treaty (including future
time extensions), (iii) in any current or future medium and for any number
of copies, and (iv) for any purpose whatsoever, including without
limitation commercial, advertising or promotional purposes (the
"License"). The License shall be deemed effective as of the date CC0 was
applied by Affirmer to the Work. Should any part of the License for any
reason be judged legally invalid or ineffective under applicable law, such
partial invalidity or ineffectiveness shall not invalidate the remainder
of the License, and in such case Affirmer hereby affirms that he or she
will not (i) exercise any of his or her remaining Copyright and Related
Rights in the Work or (ii) assert any associated claims and causes of
action with respect to the Work, in either case contrary to Affirmer's
express Statement of Purpose.

4. Limitations and Disclaimers.

 a. No trademark or patent rights held by Affirmer are waived, abandoned,
    surrendered, licensed or otherwise affected by this document.
 b. Affirmer offers the Work as-is and makes no representations or
    warranties of any kind concerning the Work, express, implied,
    statutory or otherwise, including without limitation warranties of
    title, merchantability, fitness for a particular purpose, non
    infringement, or the absence of latent or other defects, accuracy, or
    the present or absence of errors, whether or not discoverable, all to
    the greatest extent permissible under applicable law.
 c. Affirmer disclaims responsibility for clearing rights of other persons
    that may apply to the Work or any use thereof, including without
    limitation any person's Copyright and Related Rights in the Work.
    Further, Affirmer disclaims responsibility for obtaining any necessary
    consents, permissions or other rights required for any use of the
    Work.
 d. Affirmer understands and acknowledges that Creative Commons is not a
    party to this document and has no duty or obligation with respect to
    this CC0 or use of the Work.
```

## Cinc Auditor

- Project: https://cinc.sh (Cinc Project); built from Chef InSpec, https://github.com/inspec/inspec
- Version: 7.2.1 (Debian 12 package `cinc-auditor_7.2.1-1`; InSpec source tag `v7.2.1`, commit 2b6c5f8ae8bcca844d4c0909adfae32fb1fa5c48)
- Licence: Apache License 2.0. Cinc: "All our binaries are distributed under Apache 2.0 now" (https://cinc.sh/about/). Chef's own InSpec binaries need Chef's EULA and are never used.
- Copyright: Copyright (c) 2015 Chef Software Inc.; Copyright (c) 2015 Vulcano Security GmbH (as stated in the package's `/opt/cinc-auditor/LICENSE`)
- Used for: the runner image installs `cinc-auditor` so the `stig` source (`src/sources/stig.ts`) can run the STIG profiles below against a customer host, or read the InSpec JSON report a customer produced.
- Downloaded from: https://packages.cinc.sh/files/stable/cinc-auditor/7.2.1/debian/12/cinc-auditor_7.2.1-1_amd64.deb (SHA-256 7bdb16945ddbd5781ce8367a4eb5072af3f4fcc0c5c7a1639dad1c3831bcb9d4) and cinc-auditor_7.2.1-1_arm64.deb (SHA-256 d23e46096cd5c9208d79b805e46cf7077d01d39f79f456b0cacdd37746c37ed4), as listed by https://omnitruck.cinc.sh/stable/cinc-auditor/metadata?p=debian&pv=12&m=x86_64&v=7.2.1 (and m=aarch64)
- Changes: none
- Bundled with it, each under its own licence, listed in the package's `LICENSE` and kept in `/opt/cinc-auditor/LICENSES/`: Ruby 3.4.10 (Ruby licence or BSD-2-Clause), OpenSSL 3.6.4 and its FIPS provider 3.0.9 (Apache-2.0), libffi 3.8.0 (MIT), libyaml 0.2.5 (MIT), zlib 1.3.2 (zlib), the Mozilla CA bundle (MPL-2.0), and the build helper scripts `config.guess`/`config.sub` (GPL-3.0 with the Autoconf exception, which the exception lets ship with the build output).

The package's `LICENSE` file opens with this notice, as distributed; the full Apache License 2.0 text is the one reproduced under Prowler above:

```text
cinc-auditor 7.2.1 license: "Apache-2.0"

Copyright (c) 2015 Chef Software Inc.
Copyright (c) 2015 Vulcano Security GmbH.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

## MITRE SAF STIG profiles

- Project: MITRE Security Automation Framework (SAF), https://saf.mitre.org; one InSpec profile per DISA STIG, each with its dependency `mitre/inspec-profile-resources` (commit cbfb11c210cd914c69ec8caaa2bfaf0d7c45037f, the one each profile's `inspec.yml` pins)
- Versions (GitHub's tarball of each release tag; MITRE publishes no checksum, so the SHA-256 is of that tarball, also pinned in `apps/sos-app/scripts/build_stig_catalog.py`):
- `rhel9`: redhat-enterprise-linux-9-stig-baseline v2.7.2, commit e510e5292b11d43deec50c0ff0eb849693a2a6ac, SHA-256 99742c20780a4fa267ff7e4827647a3877509d2a7bda19db7d3aa925ddb676a2
- `rhel8`: redhat-enterprise-linux-8-stig-baseline v2.7.1, commit 1389331c436768956cc79d6e36b1a98431c53254, SHA-256 e4c63c518087e2241fbdc26b3af69340f4376eb50879ef02a65afe0633924032
- `ubuntu2204`: canonical-ubuntu-22.04-lts-stig-baseline v2.7.2, commit 334fdbc52e53e4ee54c4a62cdfe65c789a429b28, SHA-256 7697c7a66fd2ce72fdbc83a75430de9641d157151de2a7ee7cfb87552292637f
- `ubuntu2404`: canonical-ubuntu-24.04-lts-stig-baseline v1.4.2, commit 097246965c75b2a52325c63af17cda810e8cb22a, SHA-256 3de5186a59b33b27d5e0422a9e5255cb6c88f86be3eb3d7497c20803bbdae873
- `al2023`: amazon-linux-2023-stig-baseline v1.3.2, commit 41568eae5dccafa1c5368559cfd64d9de0ab462d, SHA-256 d01638c133c93de1e4e55d15b810f94ff9c30aa2c14760467748846e1d37aff0
- Licence: Apache License 2.0 with MITRE's redistribution conditions and NOTICE (each repository's `LICENSE.md` and `NOTICE.md`; GitHub reports the licence as "NOASSERTION" because the file is not the stock text). Each `inspec.yml` states `license: Apache-2.0` and `copyright: MITRE`.
- Copyright: The MITRE Corporation (`rhel8`'s LICENSE.md: "Copyright © 2025 The MITRE Corporation. Approved for Public Release; Distribution Unlimited. Case Number 18-3678.")
- Used for: the runner image archives each profile with its dependency (`cinc-auditor archive`) into `/opt/sagentix/stig/<profile>.tar.gz`, unmodified, and keeps each profile's `LICENSE.md` and `NOTICE.md` beside it (inside the archive, and in `/usr/share/doc/sagentix-engines/mitre-stig-<profile>/`), as MITRE's redistribution terms require. `apps/sos-app/src/data/checks/stig_<profile>.json` holds each control's id, its DISA rule id (`V-…`) and STIG id, its title and severity, and its `tag nist` controls, read from the same tarball by `build_stig_catalog.py`.
- DISA content: the rule titles, rule ids and the 800-53 references come from DISA's STIGs, which MITRE carries into the profiles. DISA prepares STIGs as a US Government work; `rhel8`'s LICENSE.md points to "https://cyber.mil/stigs/downloads for full terms of use" [Unverified: that page renders by script and its terms were not read on 2026-10-15]. The catalogues copy only titles and ids, never DISA's discussion, check or fix texts.
- Changes: none to the profiles. Which KSIs a check counts toward is Sagentix's derivation (`KSI_RULES` in the generator), not MITRE's or DISA's.
- Needs a person: MITRE's NOTICE says "No use other than those granted to the U. S. Government, or to those acting on behalf of the U. S. Government, under these contract arrangements is authorized without the express written permission of The MITRE Corporation", beside a LICENSE that grants Apache-2.0 use. MITRE ships the same NOTICE with its open-source SAF tools. Read the two together before relying on them commercially.

The LICENSE.md and NOTICE.md of `rhel9` (identical in `ubuntu2204`), as distributed; `rhel8`, `ubuntu2404` and `al2023` word them a little differently (`al2023`'s NOTICE adds that some files were written with generative AI under MITRE's review), and the image ships each one's own:

```text
Licensed under the apache-2.0 license, except as noted below.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright/ digital rights legend, this list of conditions and the following Notice.

* Redistributions in binary form must reproduce the above copyright copyright/ digital rights legend, this list of conditions and the following Notice in the documentation and/or other materials provided with the distribution.

* Neither the name of The MITRE Corporation nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
```

```text
# NOTICE

MITRE grants permission to reproduce, distribute, modify, and otherwise use this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

This software was produced by The MITRE Corporation for the U. S. Government under contract. As such the U.S. Government has certain use and data rights in this software. No use other than those granted to the U. S. Government, or to those acting on behalf of the U. S. Government, under these contract arrangements is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.
```

## Kubescape

- Project: https://github.com/kubescape/kubescape (CNCF)
- Version: 4.0.15 (git tag `v4.0.15`, commit 16cfe102f11551a6455fe9bf8e37d7083da90484)
- Licence: Apache License 2.0
- Copyright: none stated; the LICENSE appendix keeps the template line `Copyright [yyyy] [name of copyright owner]`
- Used for: the runner image bundles `kubescape` so a job can write the JSON report (`--format json`) that the `kubescape` source (`src/sources/kubescape.ts`) reads. It runs offline from `/opt/kubescape/artifacts` (the regolibrary files below), with its version check off (`KS_SKIP_UPDATE_CHECK=true`).
- Built from source: the runner image fetches the tag `v4.0.15` (commit 16cfe102f11551a6455fe9bf8e37d7083da90484) and compiles it with Go 1.27.3 (see Go below), raising modules to the floors in `collector/runner/go-module-fixes.txt`. Changes: none to the project's own source; `go.mod` and `go.sum` move only where a floor applies.
- Kubescape ships no NOTICE file at this tag.

The licence terms (sections 1 to 9 and the end of terms) are identical, word for word, to the Apache License 2.0 text reproduced under Prowler above; the file at `v4.0.15` differs only in leading white space and its appendix template.

## Kubescape regolibrary

- Project: https://github.com/kubescape/regolibrary
- Version: 2.0.38 (git tag `v2.0.38`, commit f01135a697e6f710c1797bd7cd0d2ea42ec98f9f)
- Licence: Apache License 2.0
- Copyright: none stated; the LICENSE appendix keeps the template line `Copyright [yyyy] [name of copyright owner]`
- Used for: five release assets, unmodified except that `default_config_inputs` is reduced to its `settings.postureControlInputs` (the form Kubescape reads), go to `/opt/kubescape/artifacts`: `nsa` (SHA-256 80e23ca99be3e5bb0f80d968b32ae27b7dada39f9b12b9e3abffea8680ac7737), `mitre` (66ede046cacd778b80b1afd6432288b7cb5ba44f10b6dd39f99c31f5093315f9), `attack_tracks` (80f3db3161aee990a8bab7fa0261576123fb7acf9654c595e7a47bdab339a6bb), `default_config_inputs` (6b78fae941db97d00780898da40581168303985e6dae0c74799f2c0a6ff5a8b6) and `exceptions` (d0b662af82db3fd6b2d8a242e1c7a46f47941ac7c298c2525481f817d928ddc3), as listed in checksums.txt of that release. `apps/sos-app/src/data/checks/kubescape.json` holds the control ids and names of the NSA and MITRE frameworks, read from the same `nsa` and `mitre` assets by `apps/sos-app/scripts/build_kubescape_catalog.py`. The SOC 2 and CIS frameworks are never downloaded or read.
- Changes: the `default_config_inputs` reduction above. The SP 800-53 and KSI mapping in the catalogue is Sagentix's, not Kubescape's.
- regolibrary ships no NOTICE file at this tag.

The licence terms (sections 1 to 9 and the end of terms) are identical, word for word, to the Apache License 2.0 text reproduced under Prowler above; the file at `v2.0.38` differs only in leading white space and its appendix template.

## Checkov

- Project: https://github.com/bridgecrewio/checkov
- Version: 3.3.27 (git tag `3.3.27`, commit 22ba0d2077cd3a09fc1547ae80be9ffe4e471e6c; PyPI `checkov==3.3.27`)
- Licence: Apache License 2.0
- Copyright: Copyright 2019 Palo Alto Networks (as stated in Checkov's LICENSE appendix)
- Used for: the runner image installs Checkov in `/opt/checkov` so a job can write the JSON report (`-o json`) that the `checkov` source (`src/sources/checkov.ts`) reads, with `BC_SKIP_MAPPING=TRUE` and `CKV_SKIP_PACKAGE_UPDATE_CHECK=true` so it fetches neither Prisma Cloud's mapping nor PyPI's latest version. `apps/sos-app/src/data/checks/checkov.json` names 55 Checkov check ids, each checked to exist at that tag by `apps/sos-app/scripts/build_checkov_catalog.py`; its titles and its control mapping are Sagentix's own words, not Checkov's.
- Downloaded from: https://files.pythonhosted.org/packages/26/ec/0042c3eecc84f394867554efdb25425b0b84f690997de512924850009c71/checkov-3.3.27-py3-none-any.whl (SHA-256 f162b1fee91e204cc5891baa7e3dc1775fe9843dd11a0809986b9bce806528a2, the digest PyPI lists for that file). Its Python dependencies come from PyPI at install time, unpinned, as Prowler's do.
- Changes: none
- Checkov ships no NOTICE file at this tag.

The licence terms (sections 1 to 9 and the end of terms) are identical, word for word, to the Apache License 2.0 text reproduced under Prowler above; the file at `3.3.27` differs only in leading white space and its appendix, which carries the copyright line above.
