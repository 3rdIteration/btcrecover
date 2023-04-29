# Usage Examples

This page provides links to a number of examples tht demonstrate how the setup and syntax to use BTCRecover in a number of different recovery scenarios. (Generally with a corresponding YouTube video)

The commands given can be pretty much copy/pasted as-is to allow you to recreate the examples given in the YouTube video.

**Note:** Some changes may be required based on your platform, often simple things like using "python" vs "python3".

**Python Version:** Many of these videos were created using different forks of BTCRecover. The resources and commands here may differ slightly, but are designed to work with this fork under Python3.

## Seed Recovery

[Basic Seed Recoveries](basic_seed_recoveries.md) (Demonstrates the basic commands that you would use for a recovery with various types of wallets)

[Descrambling 12 word BIP39 Seeds](Example_Descrambling_a_12_word_seed.md) (Demonstrates Using a TokenList for unscramblng seeds for Electrum Legacy, Electrum Segwit, BIP39 Bitcoin and BIP39 Ethereum)

[Multi-Device Descrambling 12 word Seed with Extra words](Example_multi_device_descrambling_12_word_seed_with_extras.md) (Demonstrates "Required" Anchors, "Positional" Anchors and Spreading Work Accross Multiple Devices) 

[Grouping words together in tokenlist based seed recoveries](example_seed_tokenlist_tokenblocks.md) (Demonstrates descrambling a 24 word seed where there several groups of words known to follow one another, but the position of these groups within the seed is unknown)

[Checking Swapped Words](example_checking_swapped_seed_words.md) (Demonstrates seed recovery where there have been two word swaps applied to words within the mnemonic)

## Password Recovery

[Basic Password Recoveries](basic_password_recoveries.md) (Demonstrates the basic commands that you would use for a recovery with various types of wallets)

[Recovering Blockchain.com Wallet Passwords](Example_Recovering_Blockchain_Wallet_Passwords.md) (Demonstrates recovering Blockchain.com wallet, using an Extract script, tokenLists, passwordlists and different types or typos)

[Multi-GPU Accelerated Recovery using Vast.ai](Example_Multi-GPU_with_vastai.md) (Demonstrates use of the vast.ai service with wallet extracts and also arguments required for mutli-gpu accelerated recovery of Blockchain.com and Bitcoin Core Wallets)

## AddressDB Creation


