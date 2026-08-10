-- Schema-only fixture definitions for the demo acquisition.
--
-- CREATE statements ONLY: no rows, no data, nothing from any real acquisition. These are
-- PhonePe's own Room-generated table shapes, reproduced so the demo case exercises the
-- real extractors rather than a mock — a screenshot of a mock would prove nothing.
--
-- Consumed by notes/make_demo_acquisition.py, which creates the databases and fills them
-- with obviously-synthetic rows. See that file's header for the safety rules.

-- ===== database: phonepe_core =====
--@DB phonepe_core
CREATE TABLE `transaction_core` (`transaction_id` TEXT NOT NULL, `type` TEXT NOT NULL, `transaction_id_type` TEXT NOT NULL, `tstore_data` TEXT, `state` TEXT NOT NULL, `unit_id` TEXT NOT NULL, `user_txn_meta` TEXT, `payment_reference` TEXT, `contact_data` TEXT, `instruments` TEXT, `timestamp_created` INTEGER NOT NULL, `timestamp_updated` INTEGER NOT NULL, `contact_data_ipn` TEXT, `show_on_history` INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(`transaction_id_type`));
CREATE TABLE transaction_aggregate_entity (
    transaction_id_type TEXT NOT NULL,
    aggregate_type TEXT NOT NULL,
    year_month TEXT NOT NULL,
    amount REAL NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(transaction_id_type),
    FOREIGN KEY(transaction_id_type) REFERENCES transaction_core(transaction_id_type) ON DELETE CASCADE
);
CREATE TABLE `chatTopic` (`topicId` TEXT NOT NULL, `subSystemType` TEXT NOT NULL, `subscriptionStatus` TEXT NOT NULL, `lastUpdated` INTEGER NOT NULL, `createdTime` INTEGER NOT NULL, PRIMARY KEY(`topicId`));
CREATE TABLE `chatTopicMeta` (`topicId` TEXT NOT NULL, `topicType` TEXT NOT NULL, `ownMemberId` TEXT NOT NULL, `topicInfo` TEXT NOT NULL, `topicName` TEXT, `state` TEXT NOT NULL, `createdTime` INTEGER, PRIMARY KEY(`topicId`));
CREATE TABLE "chatMessage" (`clientMessageId` TEXT NOT NULL, `serverMessageId` TEXT, `topicId` TEXT NOT NULL, `lastUpdated` INTEGER, `createdTime` INTEGER NOT NULL, `uploadBatchId` TEXT, `isDeleted` INTEGER, `content` TEXT, `contentType` TEXT, `syncState` INTEGER NOT NULL, `messageOperationId` TEXT, `messageOperationType` TEXT, `messageOperationTime` INTEGER, `colloquyMessageId` TEXT NOT NULL, `sourceMemberId` TEXT, `referenceMessageId` TEXT, PRIMARY KEY(`topicId`, `clientMessageId`));
CREATE TABLE `topicMember` (`memberId` TEXT NOT NULL, `connectionId` TEXT NOT NULL, `id` TEXT NOT NULL, `memberTopicId` TEXT NOT NULL, `type` TEXT NOT NULL, `role` TEXT NOT NULL, `onPhonePe` INTEGER NOT NULL, `phonePeName` TEXT, `merchantName` TEXT, `storeName` TEXT, `isMemberDeleted` INTEGER NOT NULL DEFAULT 0, `maskedPhoneNumber` TEXT, `merchantImageId` TEXT, `isGroupAccepted` INTEGER NOT NULL DEFAULT 1, `addedByMemberId` TEXT, PRIMARY KEY(`memberId`), FOREIGN KEY(`memberTopicId`) REFERENCES `chatTopicMeta`(`topicId`) ON UPDATE NO ACTION ON DELETE NO ACTION );
CREATE TABLE `phone_contacts` (`phone_num` TEXT NOT NULL, `phonepe_image_url` TEXT, `cbs_name` TEXT, `on_phonepe` INTEGER NOT NULL, `upi_enabled` INTEGER NOT NULL, `externalVpaAvailable` INTEGER NOT NULL, `validation_code` INTEGER, `connection_id` TEXT, `created_at` INTEGER NOT NULL, `updated_at` INTEGER, `ttl` INTEGER, `countryCode` TEXT, `region` TEXT, `upi_status` TEXT, PRIMARY KEY(`phone_num`));
CREATE TABLE `contactConnectionInfo` (`connectionId` TEXT NOT NULL, `name` TEXT NOT NULL, `image` TEXT, `imageType` INTEGER NOT NULL DEFAULT 0, `onPhonePe` INTEGER, `contactDisplayId` TEXT, `onMapper` INTEGER, PRIMARY KEY(`connectionId`));
CREATE TABLE `vpa_contacts` (`contact_vpa` TEXT NOT NULL, `nick_name` TEXT, `cbs_name` TEXT NOT NULL, `phonepe_image_url` TEXT, `connection_id` TEXT, `created_at` INTEGER NOT NULL, `updated_at` INTEGER NOT NULL, `change_state` INTEGER NOT NULL, `sync_state` INTEGER NOT NULL, PRIMARY KEY(`contact_vpa`));
CREATE TABLE `nonContact` (`connectionId` TEXT NOT NULL, `useCaseName` TEXT NOT NULL, `batchId` INTEGER NOT NULL, `changeState` INTEGER NOT NULL, `syncState` INTEGER NOT NULL, `phoneNumber` TEXT, `isKnown` INTEGER NOT NULL, `isHidden` INTEGER NOT NULL, `isPhoneContact` INTEGER, `countryCode` TEXT, `region` TEXT, PRIMARY KEY(`connectionId`, `useCaseName`));
CREATE TABLE `ledger_entity` (`ledger_id` TEXT NOT NULL, `topic_id` TEXT NOT NULL, PRIMARY KEY(`ledger_id`));
CREATE TABLE `ledger_expense` (`id` TEXT NOT NULL, `name` TEXT NOT NULL, `type` TEXT NOT NULL, `ledger_id` TEXT NOT NULL, `state` TEXT NOT NULL, `createdAt` INTEGER NOT NULL, `updatedAt` INTEGER, `created_by` TEXT NOT NULL, `last_updated_by` TEXT, PRIMARY KEY(`id`), FOREIGN KEY(`ledger_id`) REFERENCES `ledger_entity`(`ledger_id`) ON UPDATE NO ACTION ON DELETE CASCADE );
CREATE TABLE `ledger_expense_member` (`member_id` TEXT NOT NULL, `connection_id` TEXT NOT NULL, `is_payer` INTEGER NOT NULL, `expense_id` TEXT NOT NULL, `amount` INTEGER NOT NULL, PRIMARY KEY(`member_id`, `expense_id`, `is_payer`), FOREIGN KEY(`expense_id`) REFERENCES `ledger_expense`(`id`) ON UPDATE NO ACTION ON DELETE CASCADE );
CREATE TABLE `ledger_balance` (`member_id` TEXT NOT NULL, `connection_id` TEXT NOT NULL, `ledger_id` TEXT NOT NULL, `balanceAmountToGive` INTEGER NOT NULL, `balanceAmountToReceive` INTEGER NOT NULL, PRIMARY KEY(`member_id`), FOREIGN KEY(`ledger_id`) REFERENCES `ledger_entity`(`ledger_id`) ON UPDATE NO ACTION ON DELETE CASCADE );
CREATE TABLE `ledger_meta` (`ledgerId` TEXT NOT NULL, `createdAt` INTEGER NOT NULL, `magicSettle` INTEGER NOT NULL, `magicSettleToggleable` INTEGER NOT NULL, `magicSettleResponseCode` TEXT, PRIMARY KEY(`ledgerId`));
CREATE TABLE `ledger_my_split` (`id` TEXT NOT NULL, `other_connect_id` TEXT NOT NULL, `signed_amount` INTEGER NOT NULL, PRIMARY KEY(`id`), FOREIGN KEY(`id`) REFERENCES `ledger_split`(`split_id`) ON UPDATE NO ACTION ON DELETE CASCADE );
CREATE TABLE `ledger_settlement` (`id` TEXT NOT NULL, `global_id` TEXT NOT NULL, PRIMARY KEY(`id`), FOREIGN KEY(`id`) REFERENCES `ledger_expense`(`id`) ON UPDATE NO ACTION ON DELETE CASCADE );
CREATE TABLE `accounts` (`user_id` TEXT NOT NULL, `account_no` TEXT NOT NULL, `is_active` INTEGER, `is_linked` INTEGER, `is_primary` INTEGER, `account_limit` REAL, `max_limit` REAL, `account_type` TEXT, `usage_domain` TEXT, `account_id` TEXT NOT NULL, `branch_id` TEXT, `account_holder_name` TEXT, `pbp_creation_source` TEXT, `bank_id` TEXT, `account_ifsc` TEXT, `pbp_services_enabled` INTEGER, `allowed_cred` TEXT, `psps` TEXT, `vpas` TEXT, `account_alias` TEXT, `upi_numbers` TEXT, `is_processing` INTEGER, `upi_internation_expiry` INTEGER, `upi_international_start` INTEGER, `upi_internation_activated` INTEGER, `upi_internation_processing` INTEGER, `upi_internation_eligible` INTEGER, `upi_lite_activated` INTEGER, `upi_lite_processing` INTEGER, `upi_lite_eligible` INTEGER, `upi_lite_reference_number` TEXT, `upi_lite_account_reference_number` TEXT, `provider_account_type` TEXT, `_id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, upi_lite_auto_top_up_eligible INTEGER DEFAULT NULL, `cardBin` TEXT DEFAULT NULL, upi_lite_withdrawal_eligible INTEGER DEFAULT NULL, upi_biometric_auth_eligible INTEGER DEFAULT NULL, upi_biometric_auth_server_state TEXT DEFAULT NULL, upi_biometric_auth_reference TEXT DEFAULT NULL, upi_biometric_disabled_reason TEXT DEFAULT NULL, upi_storage_context TEXT DEFAULT NULL, co_branding_partner TEXT DEFAULT NULL, card_marketing_label TEXT DEFAULT NULL, p2p_allowed INTEGER DEFAULT null);
CREATE TABLE `vpa` (`_id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `vpa` TEXT NOT NULL, `autoGenerated` INTEGER, `expired` INTEGER, `active` INTEGER, `is_primary` INTEGER, `created_at` INTEGER, `user_id` TEXT);
CREATE TABLE `banks` (`bank_id` TEXT NOT NULL, `bank_name` TEXT, `timestamp` INTEGER, `bank_image` TEXT, `active` INTEGER, `account_creation_capability` TEXT, `banking_service_capability` TEXT, `ifsc` TEXT, `transaction_limit` TEXT, `partner` INTEGER, `premium` INTEGER, `upi_supported` INTEGER, `upi_mandate_supported` INTEGER, `net_banking_supported` INTEGER, `priority` INTEGER, `centralIfsc` TEXT, `accountNumberUniquenessOn` TEXT, `credit_card_on_upi_supported` INTEGER, `upi_lite_supported` INTEGER, `upi_credit_line_supported` INTEGER, `upi_regular_supported` INTEGER, `international_account_supported` INTEGER, `_id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, international_inward_remittance_supported INTEGER DEFAULT 0);
CREATE TABLE `consent` (`consentId` TEXT NOT NULL, `dataType` TEXT NOT NULL, `useCaseId` TEXT NOT NULL, `acceptType` TEXT NOT NULL, `consentState` TEXT NOT NULL, `endTime` INTEGER NOT NULL, `consentSyncState` TEXT NOT NULL, PRIMARY KEY(`consentId`));
CREATE TABLE "approvers_table" ( contact_number TEXT NOT NULL,
    contact_name TEXT, phonepe_image TEXT,
    local_image TEXT, approver_vpa TEXT NOT NULL,
    approver_type TEXT NOT NULL, requestor_vpa_prefix TEXT NOT NULL,
    requestor_psp_handle TEXT NOT NULL, state TEXT,
    partial_transaction_limits TEXT, `full_state` TEXT,
    `full_mandate_amount` INTEGER, `full_mandate_state` TEXT,
    `full_mandate_id` TEXT, `full_account_id` TEXT,
    `full_mandate_end_date` INTEGER, `full_linking_time` INTEGER,
    `full_remaining_balance` INTEGER, `full_umn` TEXT,
    `full_transaction_limits` TEXT, `full_document_type` TEXT,
    `full_document_id` TEXT, `full_relationship_type` TEXT,
    `full_rolling_window_balance` INTEGER, `full_balance_fetch_failure` INTEGER,

    is_consent_needed INTEGER NOT NULL,
    expiry_ts INTEGER NOT NULL,
    linking_type TEXT,
    linking_error_code TEXT, full_cool_down_until_time INTEGER DEFAULT null,
    
    PRIMARY KEY(approver_vpa)
);
CREATE TABLE `model_data` (`id` TEXT NOT NULL, `name` TEXT NOT NULL, `version` TEXT NOT NULL, `created_at` INTEGER NOT NULL, `updated_at` INTEGER NOT NULL, `state` TEXT NOT NULL, `download_uri` TEXT NOT NULL, `directory_uri` TEXT, `key` TEXT NOT NULL, `serving_state` INTEGER NOT NULL, `download_id` INTEGER, PRIMARY KEY(`id`));
CREATE TABLE `phonepe_sync_tracing` (`syncDataNature` TEXT NOT NULL, `syncId` TEXT NOT NULL, `syncStatus` TEXT NOT NULL, `systemKey` TEXT NOT NULL, `system` TEXT NOT NULL, `operation` TEXT NOT NULL, `lastSyncAttemptTime` INTEGER NOT NULL, `lastSyncCompletionTime` INTEGER NOT NULL, PRIMARY KEY(`syncId`));

-- ===== database: BullhornDatabase =====
--@DB BullhornDatabase
CREATE TABLE `topic` (`topicId` TEXT NOT NULL, `subSystemType` TEXT NOT NULL, `messageStorageType` TEXT, `messageStorageAddress` TEXT, `topicMetadata` TEXT, `topicCreatedTimeStamp` INTEGER NOT NULL, `topicUpdateTimeStamp` INTEGER NOT NULL, `oldestPointer` TEXT, `latestPointer` TEXT, `topicFlags` TEXT, `topicSubscriptionStatus` TEXT, `lastMessageSyncTime` INTEGER NOT NULL, `isRestoreSyncCompleted` INTEGER NOT NULL, `messageExpiry` INTEGER, `singleUse` INTEGER, `data` TEXT, typeOfSubscriberType TEXT NOT NULL DEFAULT 'USER', PRIMARY KEY(`topicId`));
CREATE TABLE `message` (`rowKey` TEXT NOT NULL, `messageId` TEXT NOT NULL, `topicId_M` TEXT NOT NULL, `messageOperationType` TEXT NOT NULL, `messageOperationData` TEXT, `createdTimeStamp` INTEGER, `updateTimeStamp` INTEGER, `data` TEXT, `_id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, typeOfSubscriberType_M TEXT NOT NULL DEFAULT 'USER');
CREATE TABLE `messageDataStore` (`messageId` TEXT NOT NULL, `data` TEXT, PRIMARY KEY(`messageId`));

-- ===== database: inference_data_provider =====
--@DB inference_data_provider
CREATE TABLE `sms_buffer` (`id` INTEGER NOT NULL, `time_received` INTEGER NOT NULL, `address` TEXT NOT NULL, `body` TEXT NOT NULL, `complete_meta` TEXT NOT NULL, PRIMARY KEY(`id`));

-- ===== database: accounts_db =====
--@DB accounts_db
CREATE TABLE `account` (`user_id` TEXT NOT NULL, `user_display_name` TEXT, `user_name` TEXT, `user_phone_number` TEXT, `user_email` TEXT, `email_verified` INTEGER, `phone_number_verified` INTEGER, `profile_picture` TEXT, `region_code` TEXT, `dialing_code` TEXT, `phone_num_e164` TEXT, PRIMARY KEY(`user_id`));

