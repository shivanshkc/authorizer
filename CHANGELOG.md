## [3.0.3](https://github.com/shivanshkc/authorizer/compare/v3.0.2...v3.0.3) (2025-08-23)


### Bug Fixes

* **ci:** enable delployment and refactor actions ([d57570a](https://github.com/shivanshkc/authorizer/commit/d57570a6fe4d04fc6acea5651c487584e1e1c386))

## [3.0.2](https://github.com/shivanshkc/authorizer/compare/v3.0.1...v3.0.2) (2025-03-06)


### Bug Fixes

* **ci:** signals package bug fix, better cleanup ([ef5208f](https://github.com/shivanshkc/authorizer/commit/ef5208fc40b2e11af919acef1c967337ec0217e0))

## [3.0.1](https://github.com/shivanshkc/authorizer/compare/v3.0.0...v3.0.1) (2025-02-23)


### Bug Fixes

* **ci:** no host network usage in containers, readme progress ([a64754e](https://github.com/shivanshkc/authorizer/commit/a64754ef7c75f3e03cac83bf169950c5a0d3eaa7))

# [3.0.0](https://github.com/shivanshkc/authorizer/compare/v2.3.0...v3.0.0) (2025-02-23)


* Merge pull request [#7](https://github.com/shivanshkc/authorizer/issues/7) from shivanshkc/dev ([a32102a](https://github.com/shivanshkc/authorizer/commit/a32102adf2404dfb4fae82a2d7664d671574c214))


### Bug Fixes

* **ci:** callback handler unit test fix ([6764225](https://github.com/shivanshkc/authorizer/commit/6764225cd4163a53c5569bcd8cf512914223cd49))
* **ci:** change mock provider impl to use mock.Mock ([7170436](https://github.com/shivanshkc/authorizer/commit/717043623c9382ce6990a4ad26dfe8be82126b8f))
* **ci:** update mock provider ([baffea7](https://github.com/shivanshkc/authorizer/commit/baffea7f4eabefe31af22fbf0df21e4062955596))
* **core:** cookie domain bug fix ([1184a31](https://github.com/shivanshkc/authorizer/commit/1184a31b37b7290eedc412bc06aa947119b74d17))
* **core:** fix for callback API unit test ([58f4cec](https://github.com/shivanshkc/authorizer/commit/58f4cec4ea743a4a107b9524ed2ebb8af699db08))
* **core:** make CORS handling more secure ([f579bcd](https://github.com/shivanshkc/authorizer/commit/f579bcdf51a78c92280ad18b7a7390989853b1a7))
* **core:** oauth.Google unit test fix ([3bd43cf](https://github.com/shivanshkc/authorizer/commit/3bd43cf0f268d36fad9816a1ca451f5711d87933))
* **core:** remove internal deps from oauth package ([0914bc8](https://github.com/shivanshkc/authorizer/commit/0914bc82305b2aef1bb426c88ab3c1b7171fa1dc))
* **core:** security headers ([0fffeef](https://github.com/shivanshkc/authorizer/commit/0fffeefc7b4178cbdc607daa898b8a8b9f3cef0e))
* **core:** store oauth flow context info locally ([8f992e9](https://github.com/shivanshkc/authorizer/commit/8f992e95bc99741c1860c18e07c174886dac5b42))
* **core:** unit tests for callback handler check method arguments ([b27b20b](https://github.com/shivanshkc/authorizer/commit/b27b20b655d0023d27ea8bd813f60fc47dac6401))


### Features

* **core:** add PKCE ([8e7e46a](https://github.com/shivanshkc/authorizer/commit/8e7e46ac8e02c8ca87e5b7796df007990d270844))
* **core:** add provider modularity to check API ([618bfc0](https://github.com/shivanshkc/authorizer/commit/618bfc0b14d8c1bd6ea69a240921158b7173abab))
* **core:** auth endpoint validations ([67b709a](https://github.com/shivanshkc/authorizer/commit/67b709afaac5e0f02a54180c1c78c5546bd45a85))
* **core:** database integration ([682828f](https://github.com/shivanshkc/authorizer/commit/682828f31b7c54d61e8355f3304f7cc381882fd6))
* **core:** google auth endpoint complete ([98f20a5](https://github.com/shivanshkc/authorizer/commit/98f20a537e3b7ef6e18854ba6553d2d03998adc6))
* **core:** handlers complete ([e0c974a](https://github.com/shivanshkc/authorizer/commit/e0c974a16a9e8d022131c512c6db3e1334bdafba))
* **core:** implement PKCE ([8503e43](https://github.com/shivanshkc/authorizer/commit/8503e432f5002edcf9c7ac4359ecf173537a1d6a))
* **core:** security middleware ([2ab7d13](https://github.com/shivanshkc/authorizer/commit/2ab7d1349eccdc05e8d4243ec2eabe6b39ea6006))
* **core:** state ID persistence ([e65a251](https://github.com/shivanshkc/authorizer/commit/e65a251274d12cc2095fc8d989ff30c5a75d9c36))


### BREAKING CHANGES

* Cookie usage
