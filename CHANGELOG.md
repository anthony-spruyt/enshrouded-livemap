# Changelog

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
