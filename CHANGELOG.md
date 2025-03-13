# Changelog

## [0.3.0](https://github.com/Bonial-International-GmbH/sops-check/compare/v0.2.0...v0.3.0) (2025-03-13)


### Features

* add megalinter plugin descriptor ([#56](https://github.com/Bonial-International-GmbH/sops-check/issues/56)) ([64d8814](https://github.com/Bonial-International-GmbH/sops-check/commit/64d8814b1d97f759b113d2cd66514ebb9f789869))
* add support for ignorefiles via the -i flag ([74f3621](https://github.com/Bonial-International-GmbH/sops-check/commit/74f3621b0d203d920e16be3e5b21e29af687a30e))
* add support for ignorefiles via the -i flag ([6ffdfb3](https://github.com/Bonial-International-GmbH/sops-check/commit/6ffdfb3a246ded0d683af6d3126d22ac3c1cc4a0))
* config can be remote URL ([#53](https://github.com/Bonial-International-GmbH/sops-check/issues/53)) ([33f9479](https://github.com/Bonial-International-GmbH/sops-check/commit/33f9479192a107c1d4498f1dd486a6ac538fe7c3))

## [0.2.0](https://github.com/Bonial-International-GmbH/sops-check/compare/v0.1.0...v0.2.0) (2025-02-04)


### Features

* Adds an option to display the results in a SARIF format ([#39](https://github.com/Bonial-International-GmbH/sops-check/issues/39)) ([5eec368](https://github.com/Bonial-International-GmbH/sops-check/commit/5eec36874146a29cf35296c096b107c308f4ec07))


### Bug Fixes

* **release:** always push image on main ([#25](https://github.com/Bonial-International-GmbH/sops-check/issues/25)) ([ef104e5](https://github.com/Bonial-International-GmbH/sops-check/commit/ef104e514199fe81c582c3d6b91c8b1d5a440e17))
* **release:** check for `release_created == 'true'` ([#32](https://github.com/Bonial-International-GmbH/sops-check/issues/32)) ([2fdb1cd](https://github.com/Bonial-International-GmbH/sops-check/commit/2fdb1cd97508d5a489dae120d86e5a0915a8cfe3))

## 0.1.0 (2024-11-29)


### Features

* add methods to find SOPS files ([#11](https://github.com/Bonial-International-GmbH/sops-check/issues/11)) ([61f0549](https://github.com/Bonial-International-GmbH/sops-check/commit/61f05497af13db4ff8275dc13e15f8bf62991d0c))
* basic CLI implementation ([#15](https://github.com/Bonial-International-GmbH/sops-check/issues/15)) ([ef18cf2](https://github.com/Bonial-International-GmbH/sops-check/commit/ef18cf2a65eb227fc907dbc0973ea71a36bc285b))
* implement rules engine ([#6](https://github.com/Bonial-International-GmbH/sops-check/issues/6)) ([d4345dd](https://github.com/Bonial-International-GmbH/sops-check/commit/d4345ddaa30681104b37e0f3ff1ae33aa5da9b35))


### Bug Fixes

* add LICENSE ([#16](https://github.com/Bonial-International-GmbH/sops-check/issues/16)) ([438e8fb](https://github.com/Bonial-International-GmbH/sops-check/commit/438e8fb76d1c3e59801b3e28d53cfd2f83512616))
* **config:** load YAML instead of JSON ([#9](https://github.com/Bonial-International-GmbH/sops-check/issues/9)) ([7e7fd19](https://github.com/Bonial-International-GmbH/sops-check/commit/7e7fd196b7f17d416b79f3828e65175377856314))
* copy missing files into image ([#20](https://github.com/Bonial-International-GmbH/sops-check/issues/20)) ([ddc7a84](https://github.com/Bonial-International-GmbH/sops-check/commit/ddc7a84e748cd65ef0a7012eea921d00688ccae3))
* distinguish between exact and regex matches ([#7](https://github.com/Bonial-International-GmbH/sops-check/issues/7)) ([291d8a8](https://github.com/Bonial-International-GmbH/sops-check/commit/291d8a8779d3f7d84fb75e2616771feba28f8f6d))
* do not include component name in tag ([#21](https://github.com/Bonial-International-GmbH/sops-check/issues/21)) ([5eb421f](https://github.com/Bonial-International-GmbH/sops-check/commit/5eb421fd86af91c0e62ae5f78eee3ceb3d88f35b))
* don't run the workflow on tags ([961cb50](https://github.com/Bonial-International-GmbH/sops-check/commit/961cb5010912dabf9cb544d50f3cc8b2ac5da512))
* make all packages internal ([#17](https://github.com/Bonial-International-GmbH/sops-check/issues/17)) ([7352024](https://github.com/Bonial-International-GmbH/sops-check/commit/7352024be6919b415c01725376b79eca287f9c73))
* make megalinter happy ([60c82ba](https://github.com/Bonial-International-GmbH/sops-check/commit/60c82ba19e814abb8047f02d40a152e47a11791d))
* run prettier ([1e23a8f](https://github.com/Bonial-International-GmbH/sops-check/commit/1e23a8f52b840d06edd1374d16c32567e4444388))
* update version variable ([3e55502](https://github.com/Bonial-International-GmbH/sops-check/commit/3e555027d926b89e1673941c4eafc92494b049d8))
