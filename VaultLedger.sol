// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VaultLedger
 * @author VaultLedger Team
 * @notice Decentralized ledger for local shopkeepers to record customer credit (udhaar) and payments on-chain.
 * @dev Production-grade. All shop, customer, and entry data lives on-chain. No PII on-chain — only hashed phone numbers.
 *
 * Delete model: SOFT DELETE (hidden flag).
 *   - Data is NEVER removed from blockchain. It stays forever for audit.
 *   - Hidden entries/customers are filtered out in UI via getShopSummary/getCustomerLedger.
 *   - Balance is recalculated on hide/unhide.
 *   - All operations emit events for full audit trail.
 *
 * Architecture:
 *   Shop (1 per wallet) -> Customers (many) -> Entries (many per customer)
 */

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

contract VaultLedger is Ownable, ReentrancyGuard, Pausable {

    // =============================================================
    //                          CONSTANTS
    // =============================================================

    uint256 public constant MAX_AMOUNT = 1e15;
    int256 public constant MAX_BALANCE = 1e18;
    uint256 public constant MAX_NAME_LENGTH = 64;
    uint256 public constant MAX_NOTE_LENGTH = 128;

    // =============================================================
    //                          STRUCTS
    // =============================================================

    struct Shop {
        uint256 id;
        address owner;
        string name;
        uint256 createdAt;
        uint256 customerCount;   // active (non-hidden) customers
        bool exists;
    }

    struct Customer {
        uint256 id;
        uint256 shopId;
        string name;
        bytes32 phoneHash;
        uint256 createdAt;
        int256 balance;          // active balance (excludes hidden entries)
        uint256 totalUdhaar;     // active lifetime udhaar
        uint256 totalPaid;       // active lifetime paid
        bool exists;
        bool hidden;             // soft-delete flag
        uint256 hiddenAt;
    }

    struct Entry {
        uint256 id;
        uint256 customerId;
        uint256 shopId;
        uint8 entryType;         // 0 = UDHAAR, 1 = PAYMENT, 2 = CORRECTION
        uint256 amount;
        string note;
        uint256 timestamp;
        uint256 reversesEntryId; // 0 if not a correction
        bool hidden;             // soft-delete flag
        uint256 hiddenAt;
    }

    // =============================================================
    //                          STATE
    // =============================================================

    uint256 public shopCount;
    uint256 public customerCount;
    uint256 public entryCount;

    mapping(uint256 => Shop) public shops;
    mapping(address => uint256) public walletToShopId;

    mapping(uint256 => Customer) public customers;
    mapping(uint256 => uint256[]) public shopCustomers;

    mapping(uint256 => Entry) public entries;
    mapping(uint256 => uint256[]) public customerEntries;

    mapping(uint256 => mapping(bytes32 => uint256)) public phoneHashToCustomerId;
    mapping(uint256 => bool) public entryReversed;

    // =============================================================
    //                          EVENTS
    // =============================================================

    event ShopRegistered(uint256 indexed shopId, address indexed owner, string name, uint256 timestamp);
    event ShopNameUpdated(uint256 indexed shopId, string newName, uint256 timestamp);
    event CustomerAdded(uint256 indexed shopId, uint256 indexed customerId, string name, uint256 timestamp);
    event CustomerHidden(uint256 indexed shopId, uint256 indexed customerId, uint256 timestamp);
    event CustomerRestored(uint256 indexed shopId, uint256 indexed customerId, uint256 timestamp);
    event EntryAdded(
        uint256 indexed shopId,
        uint256 indexed customerId,
        uint256 indexed entryId,
        uint8 entryType,
        uint256 amount,
        string note,
        uint256 timestamp
    );
    event EntryHidden(uint256 indexed shopId, uint256 indexed customerId, uint256 indexed entryId, uint256 timestamp);
    event EntryRestored(uint256 indexed shopId, uint256 indexed customerId, uint256 indexed entryId, uint256 timestamp);
    event EntryReversed(
        uint256 indexed shopId,
        uint256 indexed customerId,
        uint256 indexed originalEntryId,
        uint256 correctionEntryId,
        uint256 timestamp
    );

    // =============================================================
    //                        MODIFIERS
    // =============================================================

    modifier shopExists(uint256 shopId) {
        require(shops[shopId].exists, "VaultLedger: shop does not exist");
        _;
    }

    modifier onlyShopOwner(uint256 shopId) {
        require(shops[shopId].owner == msg.sender, "VaultLedger: not shop owner");
        _;
    }

    modifier customerExists(uint256 customerId) {
        require(customers[customerId].exists, "VaultLedger: customer does not exist");
        _;
    }

    modifier customerVisible(uint256 customerId) {
        require(customers[customerId].exists, "VaultLedger: customer does not exist");
        require(!customers[customerId].hidden, "VaultLedger: customer is hidden");
        _;
    }

    // =============================================================
    //                       CONSTRUCTOR
    // =============================================================

    constructor() Ownable(msg.sender) {}

    // =============================================================
    //                      SHOP FUNCTIONS
    // =============================================================

    function registerShop(string calldata name) external whenNotPaused {
        require(bytes(name).length > 0, "VaultLedger: name required");
        require(bytes(name).length <= MAX_NAME_LENGTH, "VaultLedger: name too long");
        require(!shops[walletToShopId[msg.sender]].exists, "VaultLedger: shop already exists");

        shopCount++;
        uint256 shopId = shopCount;

        shops[shopId] = Shop({
            id: shopId,
            owner: msg.sender,
            name: name,
            createdAt: block.timestamp,
            customerCount: 0,
            exists: true
        });

        walletToShopId[msg.sender] = shopId;
        emit ShopRegistered(shopId, msg.sender, name, block.timestamp);
    }

    function updateShopName(uint256 shopId, string calldata newName)
        external shopExists(shopId) onlyShopOwner(shopId) whenNotPaused
    {
        require(bytes(newName).length > 0 && bytes(newName).length <= MAX_NAME_LENGTH, "VaultLedger: invalid name");
        shops[shopId].name = newName;
        emit ShopNameUpdated(shopId, newName, block.timestamp);
    }

    // =============================================================
    //                    CUSTOMER FUNCTIONS
    // =============================================================

    function addCustomer(uint256 shopId, string calldata name, bytes32 phoneHash)
        external shopExists(shopId) onlyShopOwner(shopId) whenNotPaused returns (uint256)
    {
        require(bytes(name).length > 0, "VaultLedger: name required");
        require(bytes(name).length <= MAX_NAME_LENGTH, "VaultLedger: name too long");

        if (phoneHash != bytes32(0)) {
            uint256 existing = phoneHashToCustomerId[shopId][phoneHash];
            require(existing == 0 || customers[existing].hidden, "VaultLedger: phone already exists");
        }

        customerCount++;
        uint256 customerId = customerCount;

        customers[customerId] = Customer({
            id: customerId,
            shopId: shopId,
            name: name,
            phoneHash: phoneHash,
            createdAt: block.timestamp,
            balance: 0,
            totalUdhaar: 0,
            totalPaid: 0,
            exists: true,
            hidden: false,
            hiddenAt: 0
        });

        shopCustomers[shopId].push(customerId);
        shops[shopId].customerCount++;

        if (phoneHash != bytes32(0)) {
            phoneHashToCustomerId[shopId][phoneHash] = customerId;
        }

        emit CustomerAdded(shopId, customerId, name, block.timestamp);
        return customerId;
    }

    /**
     * @notice Soft-delete a customer. Data stays on-chain forever, hidden from UI.
     * @dev Only hidden if balance is 0 (must settle first).
     */
    function hideCustomer(uint256 customerId)
        external
        customerExists(customerId)
        whenNotPaused
        nonReentrant
    {
        Customer storage c = customers[customerId];
        require(shops[c.shopId].owner == msg.sender, "VaultLedger: not shop owner");
        require(!c.hidden, "VaultLedger: already hidden");
        require(c.balance == 0, "VaultLedger: settle balance before hiding");

        c.hidden = true;
        c.hiddenAt = block.timestamp;
        shops[c.shopId].customerCount--;

        emit CustomerHidden(c.shopId, customerId, block.timestamp);
    }

    /**
     * @notice Restore a previously hidden customer.
     */
    function restoreCustomer(uint256 customerId)
        external
        customerExists(customerId)
        whenNotPaused
        nonReentrant
    {
        Customer storage c = customers[customerId];
        require(shops[c.shopId].owner == msg.sender, "VaultLedger: not shop owner");
        require(c.hidden, "VaultLedger: not hidden");

        c.hidden = false;
        c.hiddenAt = 0;
        shops[c.shopId].customerCount++;

        emit CustomerRestored(c.shopId, customerId, block.timestamp);
    }

    // =============================================================
    //                     ENTRY FUNCTIONS
    // =============================================================

    function addEntry(
        uint256 customerId,
        uint8 entryType,
        uint256 amount,
        string calldata note
    )
        external
        customerVisible(customerId)
        whenNotPaused
        nonReentrant
        returns (uint256)
    {
        require(entryType == 0 || entryType == 1, "VaultLedger: invalid entry type");
        require(amount > 0, "VaultLedger: amount must be > 0");
        require(amount <= MAX_AMOUNT, "VaultLedger: amount exceeds max");
        require(bytes(note).length <= MAX_NOTE_LENGTH, "VaultLedger: note too long");

        Customer storage c = customers[customerId];
        require(shops[c.shopId].owner == msg.sender, "VaultLedger: not shop owner");

        entryCount++;
        uint256 entryId = entryCount;

        entries[entryId] = Entry({
            id: entryId,
            customerId: customerId,
            shopId: c.shopId,
            entryType: entryType,
            amount: amount,
            note: note,
            timestamp: block.timestamp,
            reversesEntryId: 0,
            hidden: false,
            hiddenAt: 0
        });

        customerEntries[customerId].push(entryId);

        if (entryType == 0) {
            int256 newBalance = c.balance + int256(amount);
            require(newBalance <= MAX_BALANCE, "VaultLedger: balance overflow");
            c.balance = newBalance;
            c.totalUdhaar += amount;
        } else {
            int256 newBalance = c.balance - int256(amount);
            require(newBalance >= -MAX_BALANCE, "VaultLedger: balance underflow");
            c.balance = newBalance;
            c.totalPaid += amount;
        }

        emit EntryAdded(c.shopId, customerId, entryId, entryType, amount, note, block.timestamp);
        return entryId;
    }

    /**
     * @notice Soft-delete an entry. Data stays on-chain forever, hidden from UI.
     * @dev Reverses balance impact. Entry remains visible on Etherscan.
     */
    function hideEntry(uint256 entryId)
        external
        whenNotPaused
        nonReentrant
    {
        require(entries[entryId].id != 0, "VaultLedger: entry does not exist");
        Entry storage e = entries[entryId];
        require(!e.hidden, "VaultLedger: already hidden");

        Customer storage c = customers[e.customerId];
        require(shops[c.shopId].owner == msg.sender, "VaultLedger: not shop owner");

        // Reverse balance impact
        if (e.entryType == 0) {
            int256 newBalance = c.balance - int256(e.amount);
            require(newBalance >= -MAX_BALANCE, "VaultLedger: balance underflow");
            c.balance = newBalance;
            c.totalUdhaar -= e.amount;
        } else if (e.entryType == 1) {
            int256 newBalance = c.balance + int256(e.amount);
            require(newBalance <= MAX_BALANCE, "VaultLedger: balance overflow");
            c.balance = newBalance;
            c.totalPaid -= e.amount;
        }
        // entryType == 2 (correction) — just hide, no balance change needed

        e.hidden = true;
        e.hiddenAt = block.timestamp;

        emit EntryHidden(c.shopId, e.customerId, entryId, block.timestamp);
    }

    /**
     * @notice Restore a previously hidden entry. Re-applies balance impact.
     */
    function restoreEntry(uint256 entryId)
        external
        whenNotPaused
        nonReentrant
    {
        require(entries[entryId].id != 0, "VaultLedger: entry does not exist");
        Entry storage e = entries[entryId];
        require(e.hidden, "VaultLedger: not hidden");

        Customer storage c = customers[e.customerId];
        require(shops[c.shopId].owner == msg.sender, "VaultLedger: not shop owner");

        if (e.entryType == 0) {
            int256 newBalance = c.balance + int256(e.amount);
            require(newBalance <= MAX_BALANCE, "VaultLedger: balance overflow");
            c.balance = newBalance;
            c.totalUdhaar += e.amount;
        } else if (e.entryType == 1) {
            int256 newBalance = c.balance - int256(e.amount);
            require(newBalance >= -MAX_BALANCE, "VaultLedger: balance underflow");
            c.balance = newBalance;
            c.totalPaid += e.amount;
        }

        e.hidden = false;
        e.hiddenAt = 0;

        emit EntryRestored(c.shopId, e.customerId, entryId, block.timestamp);
    }

    /**
     * @notice Reverse an entry (creates a correction entry — separate from hide).
     */
    function reverseEntry(uint256 entryId, string calldata note)
        external
        whenNotPaused
        nonReentrant
        returns (uint256)
    {
        require(entries[entryId].id != 0, "VaultLedger: entry does not exist");
        require(!entryReversed[entryId], "VaultLedger: already reversed");
        require(bytes(note).length <= MAX_NOTE_LENGTH, "VaultLedger: note too long");

        Entry storage orig = entries[entryId];
        require(!orig.hidden, "VaultLedger: entry is hidden");
        Customer storage c = customers[orig.customerId];
        require(shops[c.shopId].owner == msg.sender, "VaultLedger: not shop owner");

        entryCount++;
        uint256 correctionId = entryCount;
        uint8 correctionType = orig.entryType == 0 ? 1 : 0;

        entries[correctionId] = Entry({
            id: correctionId,
            customerId: orig.customerId,
            shopId: c.shopId,
            entryType: correctionType,
            amount: orig.amount,
            note: note,
            timestamp: block.timestamp,
            reversesEntryId: entryId,
            hidden: false,
            hiddenAt: 0
        });

        customerEntries[orig.customerId].push(correctionId);

        if (orig.entryType == 0) {
            int256 newBalance = c.balance - int256(orig.amount);
            require(newBalance >= -MAX_BALANCE, "VaultLedger: balance underflow");
            c.balance = newBalance;
            c.totalUdhaar -= orig.amount;
        } else {
            int256 newBalance = c.balance + int256(orig.amount);
            require(newBalance <= MAX_BALANCE, "VaultLedger: balance overflow");
            c.balance = newBalance;
            c.totalPaid -= orig.amount;
        }

        entryReversed[entryId] = true;
        emit EntryReversed(c.shopId, orig.customerId, entryId, correctionId, block.timestamp);
        return correctionId;
    }

    // =============================================================
    //                       VIEW FUNCTIONS
    // =============================================================

    function getShop(uint256 shopId) external view returns (Shop memory) {
        return shops[shopId];
    }

    function getShopByOwner(address owner) external view returns (Shop memory) {
        uint256 shopId = walletToShopId[owner];
        if (shopId == 0) return Shop(0, address(0), "", 0, 0, false);
        return shops[shopId];
    }

    function getCustomer(uint256 customerId) external view returns (Customer memory) {
        return customers[customerId];
    }

    function getShopCustomers(uint256 shopId) external view returns (uint256[] memory) {
        return shopCustomers[shopId];
    }

    function getCustomerEntries(uint256 customerId) external view returns (uint256[] memory) {
        return customerEntries[customerId];
    }

    function getEntry(uint256 entryId) external view returns (Entry memory) {
        return entries[entryId];
    }

    function getCustomerBalance(uint256 customerId) external view returns (int256) {
        return customers[customerId].balance;
    }

    function getCustomerByPhone(uint256 shopId, bytes32 phoneHash) external view returns (uint256) {
        return phoneHashToCustomerId[shopId][phoneHash];
    }

    // =============================================================
    //                AGGREGATED VIEWS (UI-friendly)
    // =============================================================

    struct CustomerSummary {
        uint256 id;
        string name;
        int256 balance;
        uint256 totalUdhaar;
        uint256 totalPaid;
        uint256 createdAt;
        uint256 entryCount;
        bool hidden;
    }

    struct ShopSummary {
        uint256 shopId;
        string shopName;
        uint256 customerCount;       // active (non-hidden)
        uint256 totalCustomerCount;  // all-time including hidden
        uint256 totalUdhaar;
        uint256 totalPaid;
        int256 outstanding;
        CustomerSummary[] customers;
    }

    /**
     * @notice Get full shop summary in ONE call. Includes hidden customers too (flag set).
     * @param shopId Shop ID
     * @param includeHidden If false, hidden customers are excluded from the list
     */
    function getShopSummary(uint256 shopId, bool includeHidden)
        external
        view
        shopExists(shopId)
        returns (ShopSummary memory)
    {
        Shop storage s = shops[shopId];
        uint256[] storage ids = shopCustomers[shopId];
        uint256 totalUdhaar = 0;
        uint256 totalPaid = 0;
        int256 outstanding = 0;
        uint256 activeCount = 0;

        // First pass: count
        for (uint256 i = 0; i < ids.length; i++) {
            if (!customers[ids[i]].hidden) activeCount++;
        }
        uint256 listSize = includeHidden ? ids.length : activeCount;

        CustomerSummary[] memory list = new CustomerSummary[](listSize);
        uint256 idx = 0;

        for (uint256 i = 0; i < ids.length; i++) {
            Customer storage c = customers[ids[i]];
            if (!includeHidden && c.hidden) continue;

            list[idx] = CustomerSummary({
                id: c.id,
                name: c.name,
                balance: c.balance,
                totalUdhaar: c.totalUdhaar,
                totalPaid: c.totalPaid,
                createdAt: c.createdAt,
                entryCount: customerEntries[c.id].length,
                hidden: c.hidden
            });
            idx++;

            if (!c.hidden) {
                totalUdhaar += c.totalUdhaar;
                totalPaid += c.totalPaid;
                if (c.balance > 0) outstanding += c.balance;
            }
        }

        return ShopSummary({
            shopId: s.id,
            shopName: s.name,
            customerCount: activeCount,
            totalCustomerCount: ids.length,
            totalUdhaar: totalUdhaar,
            totalPaid: totalPaid,
            outstanding: outstanding,
            customers: list
        });
    }

    function getShopStats(uint256 shopId)
        external
        view
        shopExists(shopId)
        returns (uint256 customerCount_, uint256 totalUdhaar_, uint256 totalPaid_, int256 outstanding_)
    {
        uint256[] storage ids = shopCustomers[shopId];
        uint256 totalUdhaar = 0;
        uint256 totalPaid = 0;
        int256 outstanding = 0;
        uint256 activeCount = 0;

        for (uint256 i = 0; i < ids.length; i++) {
            Customer storage c = customers[ids[i]];
            if (c.hidden) continue;
            activeCount++;
            totalUdhaar += c.totalUdhaar;
            totalPaid += c.totalPaid;
            if (c.balance > 0) outstanding += c.balance;
        }
        return (activeCount, totalUdhaar, totalPaid, outstanding);
    }

    /**
     * @notice Get paginated visible entries for a customer.
     * @param includeHidden If false, hidden entries are excluded
     */
    function getCustomerLedger(uint256 customerId, uint256 offset, uint256 limit, bool includeHidden)
        external
        view
        customerExists(customerId)
        returns (Entry[] memory)
    {
        uint256[] storage all = customerEntries[customerId];
        if (all.length == 0) return new Entry[](0);

        // Count matching entries
        uint256 matchCount = 0;
        for (uint256 i = 0; i < all.length; i++) {
            if (includeHidden || !entries[all[i]].hidden) matchCount++;
        }
        if (offset >= matchCount) return new Entry[](0);
        uint256 end = offset + limit;
        if (end > matchCount) end = matchCount;

        Entry[] memory page = new Entry[](end - offset);
        uint256 idx = 0;
        uint256 matchIdx = 0;
        for (uint256 i = 0; i < all.length && idx < end - offset; i++) {
            Entry storage e = entries[all[i]];
            if (!includeHidden && e.hidden) continue;
            if (matchIdx >= offset && matchIdx < end) {
                page[idx] = e;
                idx++;
            }
            matchIdx++;
        }
        return page;
    }

    // =============================================================
    //                       ADMIN FUNCTIONS
    // =============================================================

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}