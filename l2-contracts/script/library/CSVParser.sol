// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Vm } from "forge-std/Vm.sol";

library CSVParser {
    /**
     * @notice Loads BLS public keys, token addresses, and amounts from a CSV file
     * @param vm The Forge VM instance
     * @param csvFilePath Path to the CSV file
     * @return blsPubkeys Array of BLS public keys
     * @return tokenAddresses Array of token addresses
     * @return amounts Array of amounts
     */
    function loadBlsKeysAndAmounts(Vm vm, string memory csvFilePath)
        internal
        view
        returns (bytes[] memory blsPubkeys, address[] memory tokenAddresses, uint256[] memory amounts)
    {
        // Read the CSV file
        string memory csvContent = vm.readFile(csvFilePath);

        // Count the number of lines in the CSV
        uint256 lineCount = countLines(csvContent);

        // Initialize arrays with the appropriate size
        blsPubkeys = new bytes[](lineCount);
        tokenAddresses = new address[](lineCount);
        amounts = new uint256[](lineCount);

        // Parse each line of the CSV
        bytes memory csvBytes = bytes(csvContent);
        uint256 startIndex = 0;
        uint256 endIndex;

        for (uint256 i = 0; i < lineCount; i++) {
            // Find the end of the current line
            endIndex = findEndOfLine(csvBytes, startIndex);

            // Extract the line
            string memory line = substring(csvContent, startIndex, endIndex - startIndex);

            // Parse the line into BLS key, token address, and amount
            (string memory blsPubkeyStr, string memory tokenAddressStr, string memory amountStr) = parseCsvLine(line);

            // Convert the BLS key from hex string to bytes
            blsPubkeys[i] = vm.parseBytes(blsPubkeyStr);

            // Convert the token address from string to address
            tokenAddresses[i] = vm.parseAddress(tokenAddressStr);

            // Convert the amount from string to uint256
            amounts[i] = vm.parseUint(amountStr);

            // Move to the next line
            startIndex = endIndex + 1;
        }

        return (blsPubkeys, tokenAddresses, amounts);
    }

    /**
     * @notice Counts the number of lines in a string
     * @param str The string to count lines in
     * @return count The number of lines
     */
    function countLines(string memory str) internal pure returns (uint256 count) {
        bytes memory strBytes = bytes(str);

        if (strBytes.length == 0) return 0;

        // Start with 1 to count the first line
        count = 1;

        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == bytes1("\n")) {
                count++;
            }
        }

        // If the last character is a newline, we don't want to count an extra empty line
        if (strBytes[strBytes.length - 1] == bytes1("\n")) {
            count--;
        }

        return count;
    }

    /**
     * @notice Finds the end index of a line in a byte array
     * @param str The byte array to search in
     * @param startIndex The starting index to search from
     * @return endIndex The index of the end of the line
     */
    function findEndOfLine(bytes memory str, uint256 startIndex) internal pure returns (uint256 endIndex) {
        for (endIndex = startIndex; endIndex < str.length; endIndex++) {
            if (str[endIndex] == bytes1("\n")) {
                return endIndex;
            }
        }
        return str.length;
    }

    /**
     * @notice Extracts a substring from a string
     * @param str The source string
     * @param startIndex The starting index
     * @param length The length of the substring
     * @return result The extracted substring
     */
    function substring(string memory str, uint256 startIndex, uint256 length) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        bytes memory result = new bytes(length);

        for (uint256 i = 0; i < length; i++) {
            result[i] = strBytes[startIndex + i];
        }

        return string(result);
    }

    /**
     * @notice Parses a CSV line into BLS key, token address, and amount
     * @param line The CSV line to parse
     * @return The BLS public key as a string
     * @return The token address as a string
     * @return The amount as a string
     */
    function parseCsvLine(string memory line) internal pure returns (string memory, string memory, string memory) {
        bytes memory lineBytes = bytes(line);
        uint256 firstCommaIndex = 0;
        uint256 secondCommaIndex = 0;

        // Find the first comma
        for (uint256 i = 0; i < lineBytes.length; i++) {
            if (lineBytes[i] == bytes1(",")) {
                firstCommaIndex = i;
                break;
            }
        }

        require(firstCommaIndex > 0, "Invalid CSV format: missing first comma");

        // Find the second comma
        for (uint256 i = firstCommaIndex + 1; i < lineBytes.length; i++) {
            if (lineBytes[i] == bytes1(",")) {
                secondCommaIndex = i;
                break;
            }
        }

        require(secondCommaIndex > 0, "Invalid CSV format: missing second comma");

        // Extract BLS key, token address, and amount
        string memory blsPubkeyStr = substring(line, 0, firstCommaIndex);
        string memory tokenAddressStr = substring(line, firstCommaIndex + 1, secondCommaIndex - firstCommaIndex - 1);
        string memory amountStr = substring(line, secondCommaIndex + 1, lineBytes.length - secondCommaIndex - 1);

        return (blsPubkeyStr, tokenAddressStr, amountStr);
    }
}
