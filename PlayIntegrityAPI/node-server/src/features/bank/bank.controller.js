// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const cryptoService = require('../../services/crypto.service');
const bankPolicy = require('./bank.policy');

// In-memory store for idempotency keys (Sample App Only)
// PRODUCTION NOTE: In a real-world environment, use a distributed cache (e.g., Redis)
// or a database with atomic constraints to store idempotency keys. This ensures
// thread safety and prevents race conditions across multiple server instances.
const processedTransactions = new Set();

/**
 * Controller for handling Bank micro-app endpoints.
 */
class BankController {

    /**
     * Handles the POST request for a bank transfer.
     *
     * @param {Object} req - Express request object containing the payload and headers.
     * @param {Object} res - Express response object used to send verdicts or success data.
     * @param {Function} next - Express middleware function for error delegation.
     */
    async handleTransfer(req, res, next) {
        try {
            const payload = req.body;
            const idempotencyKey = payload.idempotencyKey;

            if (!idempotencyKey) {
                return res.status(400).json({
                    status: "ERROR",
                    error_code: "MISSING_IDEMPOTENCY_KEY",
                    message: "An idempotency key is required to process the transfer."
                });
            }

            // Validate Idempotency Key (Strict Duplicate Prevention)
            // PRODUCTION NOTE: While Play Integrity API Standard Mode provides automatic
            // replay protection, it only prevents a token from being decoded/replayed
            // excessively (typically more than ~3 times). For strict, exactly-once operations
            // like financial transfers, apps cannot rely solely on PIA's automatic replay
            // protection. You must implement your own idempotency check using a unique key.
            if (processedTransactions.has(idempotencyKey)) {
                return res.status(409).json({
                    status: "ERROR",
                    error_code: "DUPLICATE_TRANSACTION",
                    message: "A transaction with this idempotency key has already been processed."
                });
            }

            // Access the payload attached by the integrity middleware
            const tokenPayload = res.locals.integrityPayload;
            if (!tokenPayload) {
                return res.status(401).json({
                    status: "ERROR",
                    error_code: "UNAUTHORIZED",
                    message: "A valid Play Integrity token is required for the transaction."
                });
            }

            // Compute payload hash for Content Binding verification
            const serverRequestHash = cryptoService.computePayloadHash(payload);

            // Verify Content Binding
            const tokenRequestHash = tokenPayload.requestDetails?.requestHash;
            if (serverRequestHash !== tokenRequestHash) {
                return res.status(403).json({
                    status: "ERROR",
                    error_code: "REQUEST_TAMPERED",
                    message: "The request payload has been altered."
                });
            }

            // Evaluate verdicts against the Bank feature policy
            const isPolicyMet = bankPolicy.evaluateTransferPolicy(tokenPayload);

            if (!isPolicyMet) {
                return res.status(403).json({
                    status: "ERROR",
                    error_code: "INTEGRITY_REJECTED",
                    message: "Device does not meet the required security standards.",
                    remediation_code: 4,
                    remediation_action: "GET_INTEGRITY"
                });
            }

            // Register Idempotency Key
            // PRODUCTION NOTE: Register the idempotency key in Redis/DB *after* all
            // validations pass, ideally alongside the actual database transaction commit.
            processedTransactions.add(idempotencyKey);

            // Happy Path: Process transaction
            return res.status(200).json({
                status: "SUCCESS",
                transactionId: `TXN-${Math.floor(Math.random() * 1000000000)}`,
                message: "Transfer completed successfully."
            });

        } catch (error) {
            next(error);
        }
    }
}

module.exports = new BankController();