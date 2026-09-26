// Portal API, application and environment scope from request bodies and queries.
// Author: Tim Rice
// the lookups live with the labels service, the areas that take a scope keep importing it from here

const { ruleScope, previewScope } = require('../../services/labels');

module.exports = { ruleScope, previewScope };
