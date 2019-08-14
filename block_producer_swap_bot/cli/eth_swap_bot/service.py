"""
Provide implementation of the eth_swap_bot.
"""
import time
from datetime import datetime
from time import sleep

from accessify import implements
from web3 import Web3

from cli.constants import (
    ETH_CONFIRMATION_BLOCKS,
    ETH_EVENTS_WINDOW_LENGTH,
    ETH_SWAP_CONTRACT_ABI,
    ETH_SWAP_CONTRACT_ADDRESS,
    REMCHAIN_TOKEN_DECIMALS,
    REMCHAIN_TOKEN_ID,
    SHORT_POLLING_CONFIRMATION_INTERVAL,
    SHORT_POLLING_EVENTS_INTERVAL,
    ETH_ID, REMCHAIN_ID, MAX_TX_QUERIES, WAIT_FOR_ETH_NODE
)
from cli.eth_swap_bot.interfaces import EthSwapBotInterface
from cli.remchain_swap_contract.service import RemchainSwapContract
from cli.setup_logger import logger


@implements(EthSwapBotInterface)
class EthSwapBot:
    """
    Implements eth_swap_bot.
    """

    def __init__(self, eth_provider, remnode, permission, private_key):
        """
        Constructor.

        Arguments:
            eth_provider (string, required): a link to ethereum node.
            remnode (string, required): remnode script path with some options.
            permission (string, required): a permission to authorize init swap actions
        """
        self.eth_provider = eth_provider
        self.remnode = remnode
        self.permission = permission

        self.remchain_swap_contract = RemchainSwapContract(
            remnode=self.remnode,
            permission=self.permission,
            private_key=private_key,
        )

    def reload_web3(self):
        self.web3 = Web3(Web3.WebsocketProvider(self.eth_provider))

    def reload_eth_swap_contract(self):
        self.eth_swap_contract = self.web3.eth.contract(
            address=ETH_SWAP_CONTRACT_ADDRESS,
            abi=ETH_SWAP_CONTRACT_ABI
        )

    @staticmethod
    def get_swap_request_parameters(event):
        """
        Get all parameters from swap request on Ethereum.

        Arguments:
            event (object, required): an object of event on Ethereum.
        """
        event_args = event['args']
        transaction_id = str(event['transactionHash'].hex())[2:]
        chain_id = event_args['chainId'].hex()
        swap_public_key = str(event_args['swapPubkey'])
        amount_to_swap_int = int(event_args['amountToSwap'])
        return_address = event_args['returnAddress'][2:].lower()
        timestamp = int(event_args['timestamp'])
        amount = str(amount_to_swap_int)[:-REMCHAIN_TOKEN_DECIMALS] + '.' + \
            str(amount_to_swap_int)[-REMCHAIN_TOKEN_DECIMALS:] + ' ' + REMCHAIN_TOKEN_ID

        result = {
            'txid': transaction_id,
            'chain_id': chain_id,
            'swap_pubkey': swap_public_key,
            'amount': amount,
            'return_address': return_address,
            'timestamp': timestamp,
        }

        return result

    @staticmethod
    def get_event_block_number(event):
        return event.get('blockNumber')

    def wait_for_event_confirmation(self, event):
        while True:
            event_block_number = EthSwapBot.get_event_block_number(event)
            latest_block_nubmer = self.web3.eth.blockNumber
            if latest_block_nubmer - event_block_number < ETH_CONFIRMATION_BLOCKS:
                sleep(SHORT_POLLING_CONFIRMATION_INTERVAL)
            else:
                break

    def handle_swap_request_event(self, event):
        result = self.get_swap_request_parameters(event)

        txid = result.get('txid')
        timestamp = result.get('timestamp')
        result['timestamp'] = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%dT%H:%M:%S")
        result['return_chain_id'] = ETH_ID

        for i in range(0, MAX_TX_QUERIES):
            tx = self.web3.eth.getTransaction(txid)
            if tx and (self.web3.eth.blockNumber - tx.get('blockNumber') > ETH_CONFIRMATION_BLOCKS):
                if result['chain_id'] == REMCHAIN_ID:
                    self.remchain_swap_contract.init(**result)
                self.last_processed_block = self.get_event_block_number(event)
                break
            else:
                sleep(SHORT_POLLING_CONFIRMATION_INTERVAL)

    def new_swaps_loop(self, event_filter, poll_interval):
        while True:
            for event in event_filter.get_new_entries():
                self.wait_for_event_confirmation(event)
                logger.info(event)
                self.handle_swap_request_event(event)
            time.sleep(poll_interval)

    def sync_swaps_loop(self, event_filter):
        for event in event_filter.get_all_entries():
            self.wait_for_event_confirmation(event)
            logger.info(event)
            self.handle_swap_request_event(event)

    def reload_event_filter(self):
        if hasattr(self, 'last_processed_block'):
            from_block = self.last_processed_block - 1
        else:
            from_block = self.web3.eth.blockNumber - ETH_EVENTS_WINDOW_LENGTH
        self.request_swap_event_filter = self.eth_swap_contract.events.SwapRequest.createFilter(
            fromBlock=from_block, toBlock='latest',
        )

    def process_swaps(self):
        """
        Process swap requests.
        """
        while True:
            try:
                self.reload_web3()
                self.reload_eth_swap_contract()
                self.reload_event_filter()

                self.sync_swaps_loop(self.request_swap_event_filter)
                self.new_swaps_loop(self.request_swap_event_filter, SHORT_POLLING_EVENTS_INTERVAL)
            except Exception as e:
                logger.error("Exception occurred", exc_info=True)
                sleep(WAIT_FOR_ETH_NODE)
                continue

    def manual_process_swap(self, **kwargs):
        """
        Process swap request manually.
        """
        self.remchain_swap_contract.init(**kwargs)
