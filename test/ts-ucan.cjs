// works around https://github.com/ucan-wg/ts-ucan/issues/71

const lib = require("ucans")
exports.lib = lib

const { validate, build, encode, EdKeypair, RsaKeypair, parse, capability } =
  lib
exports.EdKeypair = lib.EdKeypair
exports.RsaKeypair = lib.RsaKeypair
exports.validate = validate
exports.build = build
exports.encode = encode
exports.parse = parse
exports.capability = capability
