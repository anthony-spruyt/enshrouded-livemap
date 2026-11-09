# Changelog

## [1.10.0](https://github.com/anthony-spruyt/enshrouded-livemap/compare/v1.9.1...v1.10.0) (2026-11-09)


### Features

* **compat:** check the hooks of a sigset against its exe ([#30](https://github.com/anthony-spruyt/enshrouded-livemap/issues/30)) ([a3c71c6](https://github.com/anthony-spruyt/enshrouded-livemap/commit/a3c71c6f0c985cdeadff7e780d97699a9a4d733e))


### Bug Fixes

* **boot-test:** boot the server Steam serves now ([#37](https://github.com/anthony-spruyt/enshrouded-livemap/issues/37)) ([df031a4](https://github.com/anthony-spruyt/enshrouded-livemap/commit/df031a41f55e1a50a30ed25910cd138d053e00e3))
* **compat:** check every path into a hook ([#36](https://github.com/anthony-spruyt/enshrouded-livemap/issues/36)) ([991b09b](https://github.com/anthony-spruyt/enshrouded-livemap/commit/991b09ba675531e8a5e9adc33fd83a9c10301c34))
* **compat:** record the manifest of a known build ([#34](https://github.com/anthony-spruyt/enshrouded-livemap/issues/34)) ([d9195b6](https://github.com/anthony-spruyt/enshrouded-livemap/commit/d9195b69830b13fdb790d3f785560309ad890b06))
* **fault-gate:** put the stand-in code where Wine lets the hook allocator reach it ([#39](https://github.com/anthony-spruyt/enshrouded-livemap/issues/39)) ([da7d2f2](https://github.com/anthony-spruyt/enshrouded-livemap/commit/da7d2f2e7559bb6ea9514b92da4cd01ed1f00a79)), closes [#38](https://github.com/anthony-spruyt/enshrouded-livemap/issues/38)

## [1.9.1](https://github.com/anthony-spruyt/enshrouded-livemap/compare/v1.9.0...v1.9.1) (2026-11-08)


### Bug Fixes

* **deps:** update dependency zyantific/zydis to v4.1.1 ([#26](https://github.com/anthony-spruyt/enshrouded-livemap/issues/26)) ([9d630d7](https://github.com/anthony-spruyt/enshrouded-livemap/commit/9d630d71c58fd8286d76c73e58423573a3dd0f06))

## [1.9.0](https://github.com/anthony-spruyt/enshrouded-livemap/compare/v1.8.0...v1.9.0) (2026-11-08)


### Features

* **compat:** add a tool that judges a new server build ([#21](https://github.com/anthony-spruyt/enshrouded-livemap/issues/21)) ([92c216e](https://github.com/anthony-spruyt/enshrouded-livemap/commit/92c216e6bb00ed232fa6a381dac2572a053b05b6))


### Continuous Integration

* add the data-only check and the boot test ([#19](https://github.com/anthony-spruyt/enshrouded-livemap/issues/19)) ([e0a50fd](https://github.com/anthony-spruyt/enshrouded-livemap/commit/e0a50fd802804c1555a6647d03b9db801c4cace9))

## [1.8.0](https://github.com/anthony-spruyt/enshrouded-livemap/compare/v1.7.5...v1.8.0) (2026-11-05)


### Features

* **dll:** write a FAULT line when the map crashes the server ([#18](https://github.com/anthony-spruyt/enshrouded-livemap/issues/18)) ([7887a42](https://github.com/anthony-spruyt/enshrouded-livemap/commit/7887a421c80367ac0dbacae589414bf441f4af0b))


### Dependencies

* add actionlint, MegaLinter, CI workflows and lint config ([6ae0779](https://github.com/anthony-spruyt/enshrouded-livemap/commit/6ae077944e0f6b657f4135bb52eaee2460a10ef5))
* set executable file modes ([91cd036](https://github.com/anthony-spruyt/enshrouded-livemap/commit/91cd036d6a4d29450800d6be4f635ee6f1b1b3ec))


### Documentation

* **repo-operator:** document outside Actions allowlist pattern setting ([9caabf7](https://github.com/anthony-spruyt/enshrouded-livemap/commit/9caabf79b386ab60d4e087b050116bc3e723e8e4))
* **repo-operator:** note Actions allowlist ordering in skill table ([5a50d23](https://github.com/anthony-spruyt/enshrouded-livemap/commit/5a50d23fbb0e782de41fffd06c22a7ed85f73f69))
* require full issue links and paired closing for security issues ([8615e62](https://github.com/anthony-spruyt/enshrouded-livemap/commit/8615e626804dacce96101267cb0a4d56627bbce3))


### Continuous Integration

* add a manual job that saves a server build's exe to the private store ([#16](https://github.com/anthony-spruyt/enshrouded-livemap/issues/16)) ([ca9a960](https://github.com/anthony-spruyt/enshrouded-livemap/commit/ca9a960a2e3e8061d3b02940f7bb11dea417d616))
* adopt the shared lint and CI standards ([#8](https://github.com/anthony-spruyt/enshrouded-livemap/issues/8)) ([7ba514a](https://github.com/anthony-spruyt/enshrouded-livemap/commit/7ba514a14fa80d9a07f552add0fcedfd566c67b7))
* pull the hook-check exe from the exe store ([#17](https://github.com/anthony-spruyt/enshrouded-livemap/issues/17)) ([81f3e8d](https://github.com/anthony-spruyt/enshrouded-livemap/commit/81f3e8d14431198b13668e8aaa1662306ba31c9d))
* run the build once and skip two non-link URLs in the link check ([#15](https://github.com/anthony-spruyt/enshrouded-livemap/issues/15)) ([39c61bb](https://github.com/anthony-spruyt/enshrouded-livemap/commit/39c61bbc99f9194975104a69ce1678d127e1c4f8))
* **workflows:** add packages read permission to ci job ([1b0e347](https://github.com/anthony-spruyt/enshrouded-livemap/commit/1b0e347a416fe59cb0b463de10563abab78b2abd))
* **workflows:** update release-please reusable workflow ref ([04cb6bf](https://github.com/anthony-spruyt/enshrouded-livemap/commit/04cb6bf5a04ed007dc39b7c10660ccfe47a081f8))

## [1.7.5](https://github.com/anthony-spruyt/enshrouded-livemap/compare/v1.7.4...v1.7.5) (2026-11-05)


### Bug Fixes

* clear the SonarCloud findings, keep tool paths inside --root and require a PublicUrl scheme ([#13](https://github.com/anthony-spruyt/enshrouded-livemap/issues/13)) ([cb24ec9](https://github.com/anthony-spruyt/enshrouded-livemap/commit/cb24ec9c68e90fb179b143c8a672126189cfaa77))


### Dependencies

* add docs-drift rule to sync and update wrap-up skill ([b410100](https://github.com/anthony-spruyt/enshrouded-livemap/commit/b410100e2f0ef448a8f1a6c45a4fd67af3a2a4a9))


### Documentation

* **readme:** point to data/builds.json instead of naming versions ([#11](https://github.com/anthony-spruyt/enshrouded-livemap/issues/11)) ([ef5a74a](https://github.com/anthony-spruyt/enshrouded-livemap/commit/ef5a74a938c275589db4c7c4074aef5343d5941b))

## [1.7.4](https://github.com/anthony-spruyt/enshrouded-livemap/compare/v1.7.3...v1.7.4) (2026-11-04)


### Bug Fixes

* **builds:** support server build 26430253 ([#9](https://github.com/anthony-spruyt/enshrouded-livemap/issues/9)) ([0f5635e](https://github.com/anthony-spruyt/enshrouded-livemap/commit/0f5635eefb2c4fe86c737c34af13173c542d1dd3))

## [1.7.3](https://github.com/anthony-spruyt/enshrouded-livemap/compare/v1.7.2...v1.7.3) (2026-11-04)


### Code Refactoring

* **scan:** read build signatures and offsets from data/builds.json ([9ea5156](https://github.com/anthony-spruyt/enshrouded-livemap/commit/9ea51566b6b420ce79853339c21731028d6fcd6e))

## [1.7.2](https://github.com/anthony-spruyt/enshrouded-livemap/compare/v1.7.1...v1.7.2) (2026-11-04)


### Bug Fixes

* **movement:** read the entity id table offset from the game ([#4](https://github.com/anthony-spruyt/enshrouded-livemap/issues/4)) ([922f576](https://github.com/anthony-spruyt/enshrouded-livemap/commit/922f576a592021a799bb1aea5a763ee9da291527))

## [1.7.1](https://github.com/anthony-spruyt/enshrouded-livemap/compare/v1.7.0...v1.7.1) (2026-11-04)


### Bug Fixes

* support Steam build 26319703 (community patch 0001) ([0838862](https://github.com/anthony-spruyt/enshrouded-livemap/commit/0838862ba8124608f7705f115ee9d9a4cf88886c))
* support Steam build 26404334 (community patch 0002) ([3d63e1d](https://github.com/anthony-spruyt/enshrouded-livemap/commit/3d63e1d63dbccfaa73a70cb7cd2d72094809f520))


### Dependencies

* add shared devcontainer, Claude Code, lint and GitHub config ([fd1bd3e](https://github.com/anthony-spruyt/enshrouded-livemap/commit/fd1bd3edc533cc4c80db7e5c2dd87cd0cff579f1))
* configure release-please ([808eb05](https://github.com/anthony-spruyt/enshrouded-livemap/commit/808eb053274638050429aad8e5f15f6f694ec240))
* set executable file modes ([3949379](https://github.com/anthony-spruyt/enshrouded-livemap/commit/3949379317ccdb12db9c6a5f2bbd2b563d48025d))


### Documentation

* add a fork notice to the README ([6b6f25c](https://github.com/anthony-spruyt/enshrouded-livemap/commit/6b6f25c83714a4ef369a8bc79f69277ec2aee988))
* vendor the community compatibility patches for Steam 26319703 and 26404334 ([226635c](https://github.com/anthony-spruyt/enshrouded-livemap/commit/226635c319d42602364ff8dd5b899ebec28f9778))


### Continuous Integration

* add the release workflow ([7d47ef7](https://github.com/anthony-spruyt/enshrouded-livemap/commit/7d47ef78d2e808168f7b08ba6fc8b1ccf923d2b1))
* publish the release by id and check its assets ([83aa456](https://github.com/anthony-spruyt/enshrouded-livemap/commit/83aa456445d0b9ba59d3ed9419e96e30dcbb4986))
