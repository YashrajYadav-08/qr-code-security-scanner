// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract QRReputation {
    address public owner;

    struct ReputationRecord {
        bytes32 urlHash;
        uint256 score;
        uint256 timestamp;
        bool exists;
    }

    struct Report {
        bytes32 urlHash;
        uint256 score;
        bool flaggedMalicious;
        address reporter;
        uint256 timestamp;
    }

    mapping(bytes32 => ReputationRecord) public reputationByHash;
    mapping(address => uint256) public reporterStakes;
    Report[] public reports;

    event ReputationUpdated(bytes32 indexed urlHash, uint256 score, uint256 timestamp);
    event ReportSubmitted(bytes32 indexed urlHash, bool flaggedMalicious, address reporter, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not contract owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function submitReport(bytes32 urlHash, uint256 score, bool flaggedMalicious) external {
        require(score <= 100, "Score must be between 0 and 100");

        reports.push(
            Report({
                urlHash: urlHash,
                score: score,
                flaggedMalicious: flaggedMalicious,
                reporter: msg.sender,
                timestamp: block.timestamp
            })
        );

        emit ReportSubmitted(urlHash, flaggedMalicious, msg.sender, block.timestamp);

        if (reputationByHash[urlHash].exists) {
            uint256 updatedScore = _combineScores(reputationByHash[urlHash].score, score);
            reputationByHash[urlHash].score = updatedScore;
            reputationByHash[urlHash].timestamp = block.timestamp;
        } else {
            reputationByHash[urlHash] = ReputationRecord({
                urlHash: urlHash,
                score: score,
                timestamp: block.timestamp,
                exists: true
            });
        }

        emit ReputationUpdated(urlHash, reputationByHash[urlHash].score, block.timestamp);
    }

    function getReputation(bytes32 urlHash) external view returns (ReputationRecord memory) {
        return reputationByHash[urlHash];
    }

    function setReporterStake(address reporter, uint256 amount) external onlyOwner {
        reporterStakes[reporter] = amount;
    }

    function _combineScores(uint256 currentScore, uint256 newScore) internal pure returns (uint256) {
        // Simple weighted aggregation heuristic. Production code should use a more robust
        // reputation model and validator consensus rules.
        return (currentScore + newScore) / 2;
    }
}
