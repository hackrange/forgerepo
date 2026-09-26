// Pod versions and requirements. CocoaPods' Version is RubyGems' with a dash allowed for a pre-release (2.0.0-beta.1),
// and a Podfile writes requirements the RubyGems way (~> 5.9, >= 5.0). so it is the same reading
// Author: Tim Rice

module.exports = require('../rubygems/version');
