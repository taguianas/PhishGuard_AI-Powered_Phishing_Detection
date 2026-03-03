const express = require('express');
const { body, validationResult } = require('express-validator');
const { analyzeURL } = require('../services/urlAnalyzer');
const { checkURL } = require('../threat-intel/virusTotal');
const { getDomainAge } = require('../threat-intel/domainAge');
const { checkSafeBrowsing } = require('../threat-intel/safeBrowsing');
const db = require('../database/db');
const axios = require('axios');
const requireAuth = require('../middleware/auth');

const router = express.Router();

router.post(
  '/analyze',
  requireAuth,
  [
    body('url')
      .trim()
      .isURL({ require_protocol: true })
      .withMessage('A valid URL with protocol (http/https) is required')
      .isLength({ max: 2048 })
      .withMessage('URL too long'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { url } = req.body;
      req.logger?.info({ event: 'url_scan', url });

      let hostname;
      try {
        hostname = new URL(url).hostname;
      } catch {
        return res.status(400).json({ errors: [{ msg: 'Invalid URL' }] });
      }

      // Run all async checks in parallel for speed
      const [threatIntel, domainAge, safeBrowsing, mlResult] = await Promise.all([
        // 1. VirusTotal
        checkURL(url).catch(() => null),

        // 2. Domain age via WHOIS
        getDomainAge(hostname).catch(() => null),

        // 3. Google Safe Browsing
        checkSafeBrowsing(url).catch(() => null),

        // 4. ML microservice
        process.env.ML_SERVICE_URL
          ? axios.post(`${process.env.ML_SERVICE_URL}/predict`, { url }, { timeout: 5000 })
              .then(r => r.data)
              .catch(() => null)
          : Promise.resolve(null),
      ]);

      // 5. Heuristic analysis (sync)
      const heuristics = analyzeURL(url);
      let finalScore = heuristics.risk_score;
      const reasons = [...heuristics.reasons];

      // Apply threat intel scores
      if (threatIntel?.blacklisted) {
        finalScore = Math.min(100, finalScore + 25);
        reasons.push(`Blacklisted by VirusTotal (${threatIntel.malicious} engine${threatIntel.malicious !== 1 ? 's' : ''})`);
      }

      if (domainAge?.is_young) {
        finalScore = Math.min(100, finalScore + 10);
        reasons.push(`Recently registered domain (${domainAge.age_days} days old)`);
      }

      if (safeBrowsing && !safeBrowsing.safe) {
        finalScore = Math.min(100, finalScore + 20);
        reasons.push(`Google Safe Browsing flagged: ${safeBrowsing.threats.join(', ')}`);
      }

      const classification =
        finalScore >= 70 ? 'High Risk' :
        finalScore >= 40 ? 'Medium Risk' :
        'Low Risk';

      const response = {
        url,
        risk_score: finalScore,
        classification,
        reasons,
        threat_intel: threatIntel,
        domain_age: domainAge,
        safe_browsing: safeBrowsing,
        ml_prediction: mlResult,
      };

      try {
        db.saveUrlScan({ ...response, user_id: req.user.id });
      } catch (dbErr) {
        req.logger?.error({ event: 'url_scan_db_error', message: dbErr.message });
      }

      return res.json(response);
    } catch (err) {
      req.logger?.error({ event: 'url_scan_error', message: err.message, stack: err.stack });
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

module.exports = router;
