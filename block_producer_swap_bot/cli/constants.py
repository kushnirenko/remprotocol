"""
Provide constants for command line interface.
"""
ETH_SWAP_CONTRACT_ABI = '[ { "constant": true, "inputs": [ { "name": "", "type": "uint256" } ], "name": "owners", "outputs": [ { "name": "", "type": "address" } ], "payable": false, "type": "function" }, { "constant": false, "inputs": [ { "name": "owner", "type": "address" } ], "name": "removeOwner", "outputs": [], "payable": false, "type": "function" }, { "constant": false, "inputs": [ { "name": "transactionId", "type": "uint256" } ], "name": "revokeConfirmation", "outputs": [], "payable": false, "type": "function" }, { "constant": true, "inputs": [], "name": "REMCHAIN_ID", "outputs": [ { "name": "", "type": "bytes32" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [ { "name": "", "type": "address" } ], "name": "isOwner", "outputs": [ { "name": "", "type": "bool" } ], "payable": false, "type": "function" }, { "constant": false, "inputs": [ { "name": "chainId", "type": "bytes32" }, { "name": "swapPubkey", "type": "string" }, { "name": "amountToSwap", "type": "uint256" } ], "name": "requestSwap", "outputs": [], "payable": false, "type": "function" }, { "constant": true, "inputs": [ { "name": "", "type": "uint256" }, { "name": "", "type": "address" } ], "name": "confirmations", "outputs": [ { "name": "", "type": "bool" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [ { "name": "pending", "type": "bool" }, { "name": "executed", "type": "bool" } ], "name": "getTransactionCount", "outputs": [ { "name": "count", "type": "uint256" } ], "payable": false, "type": "function" }, { "constant": false, "inputs": [ { "name": "owner", "type": "address" } ], "name": "addOwner", "outputs": [], "payable": false, "type": "function" }, { "constant": true, "inputs": [ { "name": "transactionId", "type": "uint256" } ], "name": "isConfirmed", "outputs": [ { "name": "", "type": "bool" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [ { "name": "transactionId", "type": "uint256" } ], "name": "getConfirmationCount", "outputs": [ { "name": "count", "type": "uint256" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [], "name": "MIN_SWAP_AMOUNT", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [ { "name": "", "type": "uint256" } ], "name": "transactions", "outputs": [ { "name": "destination", "type": "address" }, { "name": "value", "type": "uint256" }, { "name": "data", "type": "bytes" }, { "name": "executed", "type": "bool" }, { "name": "swapId", "type": "bytes32" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [], "name": "getOwners", "outputs": [ { "name": "", "type": "address[]" } ], "payable": false, "type": "function" }, { "constant": false, "inputs": [ { "name": "destination", "type": "address" }, { "name": "value", "type": "uint256" }, { "name": "nonce", "type": "uint256" }, { "name": "data", "type": "bytes" } ], "name": "processSwapTransaction", "outputs": [ { "name": "transactionId", "type": "uint256" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [ { "name": "from", "type": "uint256" }, { "name": "to", "type": "uint256" }, { "name": "pending", "type": "bool" }, { "name": "executed", "type": "bool" } ], "name": "getTransactionIds", "outputs": [ { "name": "_transactionIds", "type": "uint256[]" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [ { "name": "transactionId", "type": "uint256" } ], "name": "getConfirmations", "outputs": [ { "name": "_confirmations", "type": "address[]" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [], "name": "transactionCount", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "type": "function" }, { "constant": false, "inputs": [ { "name": "_required", "type": "uint256" } ], "name": "changeRequirement", "outputs": [], "payable": false, "type": "function" }, { "constant": true, "inputs": [], "name": "REMCHAIN_PUBKEY_LENGTH", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "type": "function" }, { "constant": false, "inputs": [ { "name": "transactionId", "type": "uint256" } ], "name": "confirmTransaction", "outputs": [], "payable": false, "type": "function" }, { "constant": false, "inputs": [ { "name": "destination", "type": "address" }, { "name": "value", "type": "uint256" }, { "name": "data", "type": "bytes" } ], "name": "submitTransaction", "outputs": [ { "name": "transactionId", "type": "uint256" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [], "name": "MAX_OWNER_COUNT", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "type": "function" }, { "constant": true, "inputs": [], "name": "required", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "type": "function" }, { "constant": false, "inputs": [ { "name": "owner", "type": "address" }, { "name": "newOwner", "type": "address" } ], "name": "replaceOwner", "outputs": [], "payable": false, "type": "function" }, { "constant": false, "inputs": [ { "name": "transactionId", "type": "uint256" } ], "name": "executeTransaction", "outputs": [], "payable": false, "type": "function" }, { "inputs": [ { "name": "_owners", "type": "address[]" }, { "name": "_required", "type": "uint256" } ], "payable": false, "type": "constructor" }, { "payable": true, "type": "fallback" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "sender", "type": "address" }, { "indexed": true, "name": "transactionId", "type": "uint256" } ], "name": "Confirmation", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "sender", "type": "address" }, { "indexed": true, "name": "transactionId", "type": "uint256" } ], "name": "Revocation", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "transactionId", "type": "uint256" } ], "name": "Submission", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "transactionId", "type": "uint256" } ], "name": "Execution", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "transactionId", "type": "uint256" } ], "name": "ExecutionFailure", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "sender", "type": "address" }, { "indexed": false, "name": "value", "type": "uint256" } ], "name": "Deposit", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "owner", "type": "address" } ], "name": "OwnerAddition", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "owner", "type": "address" } ], "name": "OwnerRemoval", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": false, "name": "required", "type": "uint256" } ], "name": "RequirementChange", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": false, "name": "sender", "type": "address" }, { "indexed": false, "name": "chainId", "type": "bytes32" }, { "indexed": false, "name": "swapPubkey", "type": "string" }, { "indexed": false, "name": "amountToSwap", "type": "uint256" }, { "indexed": false, "name": "timestamp", "type": "uint256" } ], "name": "SwapRequest", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": false, "name": "minSwapAmount", "type": "uint256" } ], "name": "MinSwapAmountChange", "type": "event" } ]'

ETH_SWAP_CONTRACT_ADDRESS = '0x819057C154e5B8C6b1c2baFE3c6ba57d04138345'
ETH_REM_TOKEN_ADDRESS = '0xdDB7456b6d76b6F17080439c98BB8Dad8B5Bae98'
REMCHAIN_TOKEN_ID = 'REM'
REMCHAIN_TOKEN_DECIMALS = 4

ETH_SWAP_REQUEST_EVENT_NAME = 'SwapRequest'

ETH_CONFIRMATION_BLOCKS = 3
SHORT_POLLING_CONFIRMATION_INTERVAL = 60

SHORT_POLLING_EVENTS_INTERVAL = 5  # secs

REM_SWAP_ACCOUNT = 'remio.swap'  # 'rem.swap'
PROCESS_SWAP_ACTION = 'processswap'
FINISH_SWAP_ACTION = 'finishswap'

CONFIG_FILE_NAME = 'config.ini'

ETH_EVENTS_WINDOW_LENGTH = 1_000_000
