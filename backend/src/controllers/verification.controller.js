/**
 * Verification controller.
 * Handles HTTP request/response for document verification and evidence trail inspection.
 *
 * RBAC:
 * - Verification submission: USER, HR
 * - History and details: USER/HR (own records), ADMIN/AUDITOR (all records)
 */

'use strict';

const verificationService = require('../services/verification.service');
const { success, error: errorResponse } = require('../utils/apiResponse');

/**
 * POST /api/verifications/verify
 * Upload a document to verify against issued credentials and trusted sources.
 */
const verify = async (req, res, next) => {
  try {
    if (!req.file) {
      return errorResponse(
        res,
        'Document file is required (field name: document)',
        400
      );
    }

    const verification = await verificationService.verifyDocument({
      fileBuffer: req.file.buffer,
      verifiedByUser: req.user,
      originalFilename: req.file.originalname,
      mimeType: req.file.mimetype,
    });

    return success(
      res,
      { verification },
      'Document verification completed',
      200
    );
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/verifications
 * List verification history with role-based access scoping.
 */
const list = async (req, res, next) => {
  try {
    const { result, page, limit } = req.query;
    const history = await verificationService.listVerifications({
      user: req.user,
      result,
      page,
      limit,
    });

    return success(
      res,
      history,
      'Verification history retrieved successfully'
    );
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/verifications/:id
 * Retrieve single verification record details.
 */
const getById = async (req, res, next) => {
  try {
    const verification = await verificationService.getVerification({
      verificationId: req.params.id,
      user: req.user,
    });

    return success(
      res,
      { verification },
      'Verification details retrieved successfully'
    );
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/verifications/:id/evidence
 * Retrieve the full granular evidence trail for a verification record.
 */
const getEvidence = async (req, res, next) => {
  try {
    const evidence = await verificationService.getVerificationEvidence({
      verificationId: req.params.id,
      user: req.user,
    });

    return success(
      res,
      { evidence },
      'Verification evidence trail retrieved successfully'
    );
  } catch (err) {
    next(err);
  }
};

module.exports = {
  verify,
  list,
  getById,
  getEvidence,
};
