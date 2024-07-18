# [2.3.0](https://github.com/shivanshkc/authorizer/compare/v2.2.1...v2.3.0) (2024-07-18)


### Bug Fixes

* **docs:** add new api doc ([b3f6ad4](https://github.com/shivanshkc/authorizer/commit/b3f6ad4dffc0af6393037587f5c0428ddd3c2f7e))


### Features

* **core:** add get user by email api ([2f976d2](https://github.com/shivanshkc/authorizer/commit/2f976d29dfbab9fdd6c18e58e3d865a5839d5f3d))

## [2.2.1](https://github.com/shivanshkc/authorizer/compare/v2.2.0...v2.2.1) (2024-07-18)


### Bug Fixes

* **core:** return 401 for an invalid token ([ea70e5b](https://github.com/shivanshkc/authorizer/commit/ea70e5b981b78d1fc79a7b54c9b8cbcd549acb4f))
* **docs:** update readme as per new api release [skip ci] ([4e39e37](https://github.com/shivanshkc/authorizer/commit/4e39e37461f2b0ea7b2149422c804e470465cffe))

# [2.2.0](https://github.com/shivanshkc/authorizer/compare/v2.1.0...v2.2.0) (2024-07-04)


### Features

* **core:** add get user route ([f520cf5](https://github.com/shivanshkc/authorizer/commit/f520cf5bc5c1e9accd8c255956c066c1c8670c9e))
* **core:** add token verification using google jwk ([3e21ec2](https://github.com/shivanshkc/authorizer/commit/3e21ec2dfdc29a16b2ce819f709db618afc49334))

# [2.1.0](https://github.com/shivanshkc/authorizer/compare/v2.0.2...v2.1.0) (2024-07-02)


### Bug Fixes

* **core:** disconnect from database upon interruption ([703ded4](https://github.com/shivanshkc/authorizer/commit/703ded482cb11eba206e568ea6af3e8e2f1c453c))
* **docs:** add deployment docs and api docs [skip ci] ([fa2e004](https://github.com/shivanshkc/authorizer/commit/fa2e00445c6d137ab03c3f417f3474b4d16ff572))


### Features

* **ci:** add a redirect uri allow list ([4c50e07](https://github.com/shivanshkc/authorizer/commit/4c50e07f39272477964b31094c0ae2d674a79d6d))

## [2.0.2](https://github.com/shivanshkc/authorizer/compare/v2.0.1...v2.0.2) (2024-07-02)


### Bug Fixes

* **ci:** Makefile supports both docker and podman ([d63d13f](https://github.com/shivanshkc/authorizer/commit/d63d13f57701b799b1a982d547dc1d6ea0134bda))

## [2.0.1](https://github.com/shivanshkc/authorizer/compare/v2.0.0...v2.0.1) (2024-07-02)


### Bug Fixes

* **ci:** allow deployment ([050cffd](https://github.com/shivanshkc/authorizer/commit/050cffd639885af02c04b06f04fb0786fba890ff))

# [2.0.0](https://github.com/shivanshkc/authorizer/compare/v1.1.0...v2.0.0) (2024-07-01)


### Features

* **core:** add database operations ([c302237](https://github.com/shivanshkc/authorizer/commit/c302237e00516cb274cfaef23cf334fbce902f68))
* **core:** add get user route ([5033d02](https://github.com/shivanshkc/authorizer/commit/5033d02b6f2d40db1e82ca3e8f63db19f3d5d5f1))
* **core:** callback flow complete without user insertion ([5cca86f](https://github.com/shivanshkc/authorizer/commit/5cca86fb2c446d1f96bf87d37b79d3cbb26fd576))
* **core:** make client callback url an input ([3c791eb](https://github.com/shivanshkc/authorizer/commit/3c791ebe92b0b574a5ecec2e9e6d6e4ca2fa8d2d))
* **core:** new squelette setup ([45aa01f](https://github.com/shivanshkc/authorizer/commit/45aa01f1994d87aaad4795dbb7221b2cf377cd3d))
* **core:** redirect route complete ([557235a](https://github.com/shivanshkc/authorizer/commit/557235a317116c23e064f783c3ee8d0e80c63f06))


### BREAKING CHANGES

* **core:** client callback url is a mandatory input
