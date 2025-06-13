/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity 0.7.6;

import "@openzeppelin/contracts/cryptography/ECDSA.sol";
import {MessageV2} from "../v2/MessageV2.sol";
import {AddressUtils} from "../v2/AddressUtils.sol";
import {TypedMemView} from "@summa-tx/memview-sol/contracts/TypedMemView.sol";
import {BurnMessageV2} from "../v2/BurnMessageV2.sol";

/**
 * @title TokenMessengerV2
 * @notice Sends and receives messages to/from MessageTransmitters
 * and to/from TokenMinters.
 */
contract EncodeDecoderV2 {
    // ============ Events ============
    /**
     * @notice Emitted when a DepositForBurn message is sent
     * @param burnToken address of token burnt on source domain
     * @param amount deposit amount
     * @param depositor address where deposit is transferred from
     * @param mintRecipient address receiving minted tokens on destination domain as bytes32
     * @param destinationDomain destination domain
     * @param destinationTokenMessenger address of TokenMessenger on destination domain as bytes32
     * @param destinationCaller authorized caller as bytes32 of receiveMessage() on destination domain.
     * If equal to bytes32(0), any address can broadcast the message.
     * @param maxFee maximum fee to pay on destination domain, in units of burnToken
     * @param minFinalityThreshold the minimum finality at which the message should be attested to.
     * @param hookData optional hook for execution on destination domain
     */
    event DepositForBurn(
        address indexed burnToken,
        uint256 amount,
        address indexed depositor,
        bytes32 mintRecipient,
        uint32 destinationDomain,
        bytes32 destinationTokenMessenger,
        bytes32 destinationCaller,
        uint256 maxFee,
        uint32 indexed minFinalityThreshold,
        bytes hookData
    );

    // ============ Libraries ============
    using AddressUtils for address;
    using AddressUtils for address payable;
    using AddressUtils for bytes32;
    using BurnMessageV2 for bytes29;
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    function encodeUnsignedMessageBody(
        uint32 messageBodyVersion,
        uint256 amount,
        bytes32 mintRecipient,
        address burnToken,
        address depositor,
        uint256 maxFee,
        bytes calldata hookData
    ) public pure returns (bytes memory messageBody) {
        // Format message body
        messageBody = BurnMessageV2._formatMessageForRelay(
            messageBodyVersion,
            burnToken.toBytes32(),
            mintRecipient,
            amount,
            depositor.toBytes32(),
            maxFee,
            hookData
        );
    }

    function encodeMessageBody(
        uint32 messageBodyVersion,
        uint256 amount,
        bytes32 mintRecipient,
        address burnToken,
        address depositor,
        uint256 maxFee,
        uint256 feeExecuted,
        uint256 expirationBlock,
        bytes calldata hookData
    ) public pure returns (bytes memory messageBody) {
        // Format message body
        messageBody = BurnMessageV2._formatMessageForRelay(
            messageBodyVersion,
            burnToken.toBytes32(),
            mintRecipient,
            amount,
            depositor.toBytes32(),
            maxFee,
            feeExecuted,
            expirationBlock,
            hookData
        );
    }

    function encodeUnsignedMessage(
        uint32 version,
        uint32 sourceDomain,
        uint32 destinationDomain,
        address sourceTokenMessenger,
        bytes32 destinationTokenMessenger,
        bytes32 destinationCaller,
        uint32 minFinalityThreshold,
        bytes calldata messageBody
    ) public pure returns (bytes memory message) {
        // serialize message
        message = MessageV2._formatMessageForRelay(
            version,
            sourceDomain,
            destinationDomain,
            sourceTokenMessenger.toBytes32(),
            destinationTokenMessenger,
            destinationCaller,
            minFinalityThreshold,
            messageBody
        );
    }

    function encodeMessage(
        uint32 version,
        uint32 sourceDomain,
        uint32 destinationDomain,
        address sourceTokenMessenger,
        bytes32 destinationTokenMessenger,
        bytes32 nonce,
        bytes32 destinationCaller,
        uint32 minFinalityThreshold,
        uint32 finalityThresholdExecuted,
        bytes calldata messageBody
    ) public pure returns (bytes memory message) {
        // serialize message
        message = MessageV2._formatMessageForRelay(
            version,
            sourceDomain,
            destinationDomain,
            nonce,
            sourceTokenMessenger.toBytes32(),
            destinationTokenMessenger,
            destinationCaller,
            minFinalityThreshold,
            finalityThresholdExecuted,
            messageBody
        );
    }

    function decodeMessage(
        bytes calldata _message
    ) public view returns (
        uint32 version,
        uint32 sourceDomain,
        uint32 destinationDomain,
        address sourceTokenMessenger,
        bytes32 destinationTokenMessenger,
        bytes32 nonce,
        bytes32 destinationCaller,
        uint32 minFinalityThreshold,
        uint32 finalityThresholdExecuted,
        bytes memory messageBody
    ) {

        bytes29 _msg = _message.ref(0);

        MessageV2._validateMessageFormat(_msg);
        version = MessageV2._getVersion(_msg);
        destinationDomain = MessageV2._getDestinationDomain(_msg);
        destinationCaller = MessageV2._getDestinationCaller(_msg);
        nonce = MessageV2._getNonce(_msg);
        sourceDomain = MessageV2._getSourceDomain(_msg);
        sourceTokenMessenger = MessageV2._getSender(_msg).toAddress();
        destinationTokenMessenger = MessageV2._getRecipient(_msg);
        minFinalityThreshold = MessageV2._getMinFinalityThreshold(_msg);
        finalityThresholdExecuted = MessageV2._getFinalityThresholdExecuted(_msg);
        messageBody = MessageV2._getMessageBody(_msg).clone();
    }

    function decodeMessageBody(
        bytes calldata _messageBody
    ) public view returns (
        uint32 messageBodyVersion,
        uint256 amount,
        bytes32 mintRecipient,
        address burnToken,
        address depositor,
        uint256 maxFee,
        uint256 feeExecuted,
        uint256 expirationBlock,
        bytes memory hookData
    ) {
        // uint256 ADDRESS_BYTE_LENGTH = 20;
        bytes29 messageBody = _messageBody.ref(0);
        messageBody._validateBurnMessageFormat();

        messageBodyVersion = messageBody._getVersion();
        expirationBlock = messageBody._getExpirationBlock();
        amount = messageBody._getAmount();
        mintRecipient = messageBody._getMintRecipient();
        burnToken = messageBody._getBurnToken().toAddress();
        depositor = messageBody._getMessageSender().toAddress();
        maxFee = messageBody._getMaxFee();
        feeExecuted = messageBody._getFeeExecuted();

        bytes29 _hookData = messageBody._getHookData();
        if (_hookData.isValid()) {
            hookData = _hookData.clone();
            // uint256 _hookDataLength = _hookData.len();
            // if (_hookDataLength >= ADDRESS_BYTE_LENGTH) {
            //     address _target = _hookData.indexAddress(0);
            //     bytes memory _hookCalldata = _hookData
            //         .postfix(_hookDataLength - ADDRESS_BYTE_LENGTH, 0)
            //         .clone();

            //     (hookSuccess, hookReturnData) = _executeHook(
            //         _target,
            //         _hookCalldata
            //     );
            // }
        }

    }
    function recoverAttesterSignature(
        bytes32 _digest,
        bytes memory _signature
    ) public pure returns (address) {
        return (ECDSA.recover(_digest, _signature));
    }
    function verifyAttestationSignatures(
        bytes calldata _message,
        bytes calldata _attestation,
        uint256 signatureThreshold
    ) public pure returns (bool success, address[] memory signers, string memory info) {
        uint256 signatureLength = 65;

        if ( _attestation.length != signatureLength * signatureThreshold) {
            info = "Invalid attestation length";
            return (success, signers, info);
        }

        // (Attesters cannot be address(0))
        address _latestAttesterAddress = address(0);
        // Address recovered from signatures must be in increasing order, to prevent duplicates

        bytes32 _digest = keccak256(_message);

        for (uint256 i; i < signatureThreshold; ++i) {
            bytes memory _signature = _attestation[i * signatureLength:i *
                signatureLength +
                signatureLength];

            address _recoveredAttester = recoverAttesterSignature(
                _digest,
                _signature
            );

            if (_recoveredAttester <= _latestAttesterAddress) {
                info = "Invalid signature order or dupe";
                return (success, signers, info);
            }
            signers[i] = _recoveredAttester;
            _latestAttesterAddress = _recoveredAttester;
        }
    }

}
