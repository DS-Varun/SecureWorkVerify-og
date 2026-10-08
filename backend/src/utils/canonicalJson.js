/**
 * Canonical JSON serialization utility.
 *
 * Deterministically serializes JavaScript objects/values to a canonical JSON string
 * by recursively sorting object keys.
 *
 * Requirements:
 * - Deterministic output regardless of property insertion order
 * - Handles primitives, arrays, nested objects, null, undefined, Dates, and MongoDB ObjectIds
 * - Zero external dependencies
 */

'use strict';

/**
 * Recursively normalizes an arbitrary value for canonical serialization.
 * @param {*} value
 * @returns {*}
 */
const normalizeValue = (value) => {
  if (value === null || value === undefined) {
    return value;
  }

  // If value is a Date, serialize to ISO string
  if (value instanceof Date) {
    return value.toISOString();
  }

  // If value has a custom toJSON method or is a Mongoose ObjectId / BSON type
  if (typeof value === 'object' && typeof value.toHexString === 'function') {
    return value.toHexString();
  }

  // If value is an array, normalize each item
  if (Array.isArray(value)) {
    return value.map(normalizeValue);
  }

  // If value is a plain object, recursively sort keys
  if (typeof value === 'object') {
    // If it has toJSON (and not a buffer), call toJSON first
    if (typeof value.toJSON === 'function' && typeof value.toHexString !== 'function') {
      return normalizeValue(value.toJSON());
    }

    const sortedKeys = Object.keys(value).sort();
    const result = {};
    for (const key of sortedKeys) {
      const val = value[key];
      if (val !== undefined) {
        result[key] = normalizeValue(val);
      }
    }
    return result;
  }

  return value;
};

/**
 * Deterministically stringifies any JavaScript value with sorted object keys.
 * @param {*} data
 * @returns {string} Canonical JSON string
 */
const canonicalStringify = (data) => {
  const normalized = normalizeValue(data);
  return JSON.stringify(normalized !== undefined ? normalized : null);
};

module.exports = { canonicalStringify, normalizeValue };
