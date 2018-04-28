import os
import plyvel
import struct
from datetime import datetime
import hashlib
import shutil
import time

# uncomment if run with parse.py in ide

# whileplyvel.DB(path + '/waiting_blocks', create_if_missing=True)

'''
Here is how a block is read.

Step #1 : We read the block format version
Step #2 : We read the hash of the previous block
Step #3 : We read the merkle root hash
Step #4 : We read the block time stamp
Step #5 : We read a 'bits' field; internal use defined by the bitcoin software
Step #6 : We read the 'nonce' value; a randum number generated during the mining process.
Step #7 : We read the transaction count
Step #8 : For/Each Transaction
          : (a) We read the transaction version number.
          : (b) We read the number of inputs.
Step #8a : For/Each input
			: (a) Read the hash of the input transaction
			: (b) Read the input transaction index
			: (c) Read the response script length
			: (d) Read the response script data; parsed using the bitcoin scripting system; a little virtual machine.
Step #8aa	: (a) Read the sequence number.
			: (b) Read the number of outputs
Step #8b : For/Each Output
			: (a) Read the value of the output in BTC fixed decimal; see docs.
			: (b) Read the length of the challenge script.
			: (c) Read the challenge script
Step #9 Read the LockTime; a value currently always hard-coded to zero

Refer symbols like B1 to http://2.bp.blogspot.com/-DaJcdsyqQSs/UsiTXNHP-0I/AAAAAAAATC0/kiFRowh-J18/s1600/blockchain.png.
'''

MAGIC_ID = '\xf9\xbe\xb4\xd9'

path = '.'

class Block(object):
    def __init__(self,header=None,transactions=None):
        self.header = header # instance of Blockheader class
        self.transactions = transactions # instance of Transaction class
        self.num_txn = None
        self.blocksize = None
        # self.num_tx = len(self.transactions)

    def processBlock(self,data,pos):

        startIndex = pos

        header = BlockHeader()
        endIndex, pos = header.processBlockHeader(data, pos)

        # check whether prev_hash is found in processed_db (pos is None)
        # if prev_hash is not found, put current block into waitlist
        if pos is None:

            cur_block = data[startIndex:endIndex]
            waiting_blocks = waiting_blocks_db.get(header.prev_hash)
            if waiting_blocks is None:
                waiting_blocks = [cur_block]
            else:
                waiting_blocks = eval(waiting_blocks)
                waiting_blocks.append(cur_block)
            waiting_blocks_db.put(header.prev_hash,bytes(waiting_blocks))

            # print "Putting current block into waiting list..."

            return endIndex, None

        # else process current block, along with all the blocks in the waitlist that points to it
        else:

            '''process current block'''
            txn_in_block = []

            # B9 varianble length integer
            num_tx, pos = varint(data, pos)
            # print "Number of transactions: %d" % num_tx

            # go into transactions
            for i in range(num_tx):

                txn = Transaction()

                pos = txn.processTransaction(data,pos)

                txn_in_block.append(txn)

            assert endIndex == pos, "Wrong index at the end of the counter! Ending index should be %d, but got %d instead." \
                                    % (endIndex, pos)

            self.header = header
            self.transactions = txn_in_block
            self.num_txn = len(self.transactions)
            # self.blocksize = header.header_length

            # put current block's hash into processed_blocks database
            processed_blocks_db.put(self.header.hashcash,bytes(1))

            '''return all the blocks in the waitlist that point to it'''
            block_hash = self.header.hashcash
            child_blocks = [] # return, for writing to
            raw_child_blocks = waiting_blocks_db.get(block_hash)
            if raw_child_blocks is not None:
                child_blocks=eval(raw_child_blocks)
                # print raw_child_blocks
                # for cb in raw_child_blocks:
                #     block = Block()
                #     block.processBlock(cb,0)
                #     child_blocks.append(block)
                # processed_blocks_db.put(block.header.hashcash,bytes(1))
                # waiting_blocks_db.delete(block_hash)
            return pos, child_blocks  # child_blocks: a list of raw blocks


class BlockHeader(object):
    def __init__(self,magic_id=None,header_length=None, version_number=None,prev_hash_raw=None,merkle_hash_raw=None,timestamp=None,bits=None,nonce=None):
        self.magic_id = magic_id
        self.header_length = header_length
        self.version_number = version_number
        self.prev_hash_raw = prev_hash_raw
        self.prev_hash = None
        self.merkle_hash_raw = merkle_hash_raw
        self.merkle_hash = None
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.hashcash = None
        self.blocksize = None

    def calculateHashcash(self):

        header_bin = struct.pack(
            '<I32s32sIII',
            self.version_number,
            self.prev_hash_raw,
            self.merkle_hash_raw,
            self.timestamp,
            self.bits,
            self.nonce,
        )
        # The named constructors are much faster than new()
        # and should be preferred.
        h = hashlib.sha256(
            hashlib.sha256(header_bin).digest()
        ).digest()

        self.hashcash = h[::-1].encode('hex')

        return self.hashcash

    def processBlockHeader(self,data,pos):

        startIndex = pos
        # B1 magic id, need to convert from little endian to big endian
        self.magic_id = data[pos:pos + 4]
        # print magic_id
        assert MAGIC_ID == self.magic_id, "A magic_id mismatch found at position %d! Found: %s" % (pos,  self.magic_id)
        pos += 4

        # B2 read block size -- length of block = headerlength + 8(B1+B2)
        self.header_length = struct.unpack_from('<I', data, offset=pos)[0]
        pos += struct.calcsize('<I')

        endIndex = self.header_length + pos  # for checking index at the end of each block

        self.blocksize = endIndex - startIndex

        # B3-7
        # unsigned int32 version - 4 bytes
        # 32 bytes of previous hash
        # 32 bytes of merkle hash
        # unsigned int32 time - 4 bytes
        # unsigned int32 bits - 4 bytes
        # unsigned int32 nonce - 4 bytes

        self.version_number, self.prev_hash_raw = struct.unpack_from('<I32s',data, offset=pos)

        pos += struct.calcsize('<I32s')

        self.prev_hash = self.prev_hash_raw[::-1].encode('hex')

        # check whether prev_hash is processed
        processed = processed_blocks_db.get(self.prev_hash)

        if processed is None:  # previous block not found!!!
            return endIndex, None

        self.merkle_hash_raw, self.timestamp, self.bits, self.nonce = struct.unpack_from('<32sIII', data,offset=pos)

        # compute hash from raw
        self.merkle_hash = self.merkle_hash_raw[::-1].encode('hex')

        self.calculateHashcash()

        pos += struct.calcsize('<32sIII')

        return endIndex, pos

class Transaction(object):
    def __init__(self,input_txn=None, output_txn=None):
        # self.num_tx = num_tx
        self.input_txn = input_txn
        self.output_txn = output_txn
        self.num_input = None
        self.num_output = None
        self.version_number = None
        self.lock_time = None
        self.txn_hash = None
        self.txn_fee = 0

    def processTransaction(self,data,pos):

        txn_start_index = pos

        input_txn, output_txn = [], []

        # T1 transaction version number
        self.version_number = struct.unpack_from('<I', data, offset=pos)[0]
        pos += struct.calcsize('<I')

        # T2 varianble length integer
        num_input, pos = varint(data, pos)

        # print "Number of input transactions in transaction No. %d: %d" % (num_tx, num_input)

        for j in range(num_input):
            txn = InputTransaction()
            pos = txn.processInputTransactions(data, pos)
            input_txn.append(txn)

        # T3 varianble length integer
        num_output, pos = varint(data, pos)

        # print "Number of output transactions in transaction No. %d: %d" % (num_tx, num_output)

        output_starts, output_ends = [], []
        for k in range(num_output):
            tx = OutputTransaction()
            output_starts.append(pos)
            pos = tx.processOutputTransactions(data, pos)
            output_ends.append(pos)
            output_txn.append(tx)

        # T4 transaction lock time
        self.lock_time = struct.unpack_from('<I', data, offset=pos)[0]
        pos += struct.calcsize('<I')

        self.input_txn, self.output_txn  = input_txn, output_txn
        # self.calculateTransactionFee()
        self.num_input = num_input
        self.num_output = num_output

        self.txn_hash = hashlib.sha256(hashlib.sha256(data[txn_start_index:pos]).digest()).digest()[::-1].encode('hex')

        # put every output transaction in this transaction into the leveldb database
        # key: type: string, transaction + output_txn index, value: type: bytearray, output
        for i in range(num_output):
            utxo_db.put(self.txn_hash + str(i), data[output_starts[i]:output_ends[i]])
            # if self.txn_hash == '0aa3da5441c78465f77466e62c73cd29a7131381b1a06bc63af04f625fa6b658':
            #     print i

        return pos

class InputTransaction(object):
    def __init__(self,prev_hash=None, tx_index=None, script_sig=None, seq_no=None):
        self.prev_hash = prev_hash
        self.tx_index = tx_index
        self.script_sig = script_sig
        self.seq_no = seq_no
        self.is_coinbase = False

    def processInputTransactions(self,data, pos):
        # I1 transaction hash
        prev_hash = struct.unpack_from('<32s', data, offset=pos)[0]
        pos += struct.calcsize('<32s')

        # I2 transaction index
        tx_index = struct.unpack_from('<I', data, offset=pos)[0]
        pos += struct.calcsize('<I')

        # I3 varianble length integer
        script_length, pos = varint(data, pos)

        # I4 input script
        script_sig_seq_no_fmt = '<{}sI'.format(script_length)
        script_sig, seq_no = struct.unpack_from(
            script_sig_seq_no_fmt,
            data,
            offset=pos
        )
        pos += struct.calcsize(script_sig_seq_no_fmt)

        if tx_index == 0xffffffff: # new coin mined, will not take into consideration to transaction fees
            self.is_coinbase = True

        self.prev_hash, self.tx_index, self.script_sig, self.seq_no  = prev_hash, tx_index, script_sig, seq_no

        self.prev_hash = self.prev_hash[::-1].encode('hex')
        return pos

class OutputTransaction(object):
    def __init__(self, value=None, public_key=None ):
        self.value = value
        self.public_key = public_key

    def processOutputTransactions(self, data, pos):
        # O1 value
        value, = struct.unpack_from('<q', data, offset=pos)
        pos += struct.calcsize('<q')

        # O2 variable length integer
        public_key_length, pos = varint(data, pos=pos)

        # O3 public key
        public_key_fmt = '<{}s'.format(public_key_length)
        public_key, = struct.unpack_from(public_key_fmt, data, offset=pos)
        pos += struct.calcsize(public_key_fmt)

        self.value, self.public_key = value, public_key
        # print self.public_key.encode('hex'), self.value

        # hash public key
        # hashlib.sha256(self.public_key.encode('hex'))

        return pos


class Parser(object):
    def __init__(self,db_path=None):
        pass

    def __del__(self):
        pass
        # self.db.close()

    def parser_repo(self,repo):

        repo = repo if  repo.endswith('/') else repo +'/'
        dat_list = []
        for i in os.listdir(repo):
            if i.endswith('.dat') and i.startswith('blk'):
                dat_list.append(i)

        # if no .dat file found
        if dat_list == []:
            print 'No .dat file found!'
            return
        dat_list = sorted(dat_list)

        start_time = time.time()
        for file in dat_list:
            filename = repo+file
            f = open(filename,'r')
            t = time.time()
            self.parse_file(f,filename)
            s = time.time()

            log.write("Time elapsed for processing %s: %s\n" % (file,str(time.strftime("%H:%M:%S" , time.gmtime(s-t)))))

        finish_time = time.time()

        log.write("Total Time elapsed: %s\n" % str(time.strftime("%H:%M:%S" , time.gmtime(finish_time-start_time))))

        log.close()

    def parse_file(self,f,dat_file):

        print "Start processing %s" % dat_file
        # f = open(dat_file,'r')
        cur_date = 0

        data = f.read()

        pos = 0 # current position

        blocks_in_one_day = []

        block_counter = 0

        num_blocks_writen = 0

        printed = False

        while(1):

            if not printed and block_counter % 10000 == 1:# or block_counter > 90000:
                print "Processed %d blocks." % block_counter
                # printed = True

            block_counter += 1

            block = Block()

            # startIndex = pos

            pos, child_blocks = block.processBlock(data,pos)

            # endIndex = pos

            # if block_counter>=92025:
            #     print block.transactions[1].output_txn.public_key

            # child_blocks is None means that the previous block is not processed, current block put in waiting_db
            # otherwise it means that the previous block is processed, and current block processed
            if child_blocks is not None:

                block_date = datetime.fromtimestamp(block.header.timestamp).date()

                if cur_date == 0: # first block
                    cur_date = block_date
                    blocks_in_one_day.append(block)

                elif cur_date == block_date: # blocks in the same day
                    blocks_in_one_day.append(block)

                else: # blocks in a new day
                    # write down previous blocks to csv file
                    filename = path+'/blocks/Blocks_'+str(cur_date)+'.csv'
                    if os.path.exists(filename):
                        file = open(filename,'a')
                    else:
                        file = open(filename, 'w+')
                        self.writeHeader(file)
                    for i in xrange(len(blocks_in_one_day)):
                        self.writeBlock(file,blocks_in_one_day[i])
                    file.close()

                    num_blocks_writen += 1

                    # start collecting new blocks
                    cur_date = block_date
                    blocks_in_one_day = [block]

                # process child blocks
                if child_blocks != []:
                    while child_blocks!=[]:
                        grandchild_blocks = []
                        for cb in child_blocks:
                            child_block = Block()
                            _, tmp_block = child_block.processBlock(cb,0)
                            if tmp_block != []:
                                grandchild_blocks += tmp_block

                            # write down child block
                            cb_block_date = datetime.fromtimestamp(child_block.header.timestamp).date()
                            cb_filename = path+'/blocks/Blocks_' + str(cb_block_date) +'.csv'

                            num_blocks_writen += 1

                            if os.path.exists(cb_filename):
                                cb_file = open(cb_filename,'a')
                                self.writeBlock(cb_file, child_block)
                            else:
                                cb_file = open(cb_filename,'w+')
                                self.writeHeader(cb_file)
                                self.writeBlock(cb_file, child_block)
                            cb_file.close()

                        child_blocks = grandchild_blocks

                        # delete hash of previous blocks in waiting list
                        waiting_blocks_db.delete(child_block.header.prev_hash)

            # in case there are useless symbols between two blocks, as mentioned in http://codesuppository.blogspot.com/2014/01/how-to-parse-bitcoin-blockchain.html
            skipped_bytes = 0
            while pos<len(data) and struct.unpack_from('<4s', data, offset=pos)[0] != '\xf9\xbe\xb4\xd9':
                print "not a new block!"
                skipped_bytes += 1
                pos += 1
            if skipped_bytes != 0:
                print "Skipped %d bytes while processing %s." % (skipped_bytes, dat_file)


            if pos == len(data):
                print '%d blocks processed in file %s. %d blocks written to csv file. ' %(block_counter, dat_file, num_blocks_writen)
                log.write('%d blocks processed in file %s. %d blocks written to csv file.\n' %(block_counter, dat_file, num_blocks_writen))
                return


    def writeHeader(self,file):
        file.write("Date, Block Hash, Transaction size, Tranaction No., Number of inputs, \
        Number of outputs, Input hash, Input Value, Output hash, Output Value, Transaction Fee\n")


    def writeBlock(self,file, block):
        num_txn = len(block.transactions)

        # TODO: 1. block_counter --> omit for the moment
        # Date, block hash, number of transactions in this block
        file.write("%s, %s, %d,"%
                   (datetime.fromtimestamp(block.header.timestamp).date(),block.header.hashcash, num_txn))

        for i in xrange(num_txn): # every single transaction
            if i != 0:
                file.write(",,,")
            txn_fee = 0

            # transaction number, number of inputs, number of outputs
            file.write("%d,  %d, %d," %
                       (i+1, block.transactions[i].num_input, block.transactions[i].num_output))

            # continue to write the first transaction on the same line
            if block.transactions[i].num_input > 0:

                if block.transactions[i].input_txn[0].is_coinbase: # input transaction from coinbase, no need to write
                    file.write(',,')

                else:# input transaction from unspent output, write down
                    txn_hash = block.transactions[i].input_txn[0].prev_hash
                    index = block.transactions[i].input_txn[0].tx_index
                    key = txn_hash+str(index)
                    prev_output_raw = utxo_db.get(key)
                    if not prev_output_raw:
                        print "Ah, input transaction not found in database! Block hash: %s. Input transaction hash: %s Index: %d" % (block.header.hashcash,txn_hash,index)
                        exit()
                        file.write(",,")
                    else:
                        prev_output = OutputTransaction()
                        prev_output.processOutputTransactions(prev_output_raw,0)
                        txn_fee += prev_output.value
                        file.write("%s, %d," % (prev_output.public_key.encode("hex"), prev_output.value))
                        # delete if utxo has been spent
                        # if date >  Jan 2017, don't delete
                        if datetime.utcfromtimestamp(block.header.timestamp) > datetime(2016,12,31):
                            utxo_db.delete(key)

            if block.transactions[i].num_output > 0:
                if txn_fee != -1:
                    txn_fee -= block.transactions[i].output_txn[0].value
                    # print txn_fee

                file.write("%s, %d," % (block.transactions[i].output_txn[0].public_key.encode('hex'),
                                         block.transactions[i].output_txn[0].value))
                file.write("\n")

            count = max(block.transactions[i].num_input, block.transactions[i].num_output)

            # write other parts in new lines
            for j in xrange(1,count):
                file.write(",,,,,,")
                # input hash, input value
                if j<block.transactions[i].num_input:
                    txn_hash = block.transactions[i].input_txn[j].prev_hash
                    index = block.transactions[i].input_txn[j].tx_index
                    key = txn_hash + str(index)
                    prev_output_raw = utxo_db.get(key)
                    if not prev_output_raw:
                        print "Ah, input transaction not found in database! Block hash: %s. Input hash: %s" % (block.header.hashcash,txn_hash)
                        exit()
                        file.write(",,")
                    else:
                        prev_output = OutputTransaction()
                        prev_output.processOutputTransactions(prev_output_raw,0)
                        txn_fee += prev_output.value
                        file.write("%s, %d," % (prev_output.public_key.encode("hex"), prev_output.value))
                        # delete if utxo has been spent
                        # if date >  Jan 2017, don't delete
                        if datetime.utcfromtimestamp(block.header.timestamp) > datetime(2016, 12, 31):
                            utxo_db.delete(key)
                else:
                    file.write(",,")

                # output hash, output value
                if j<block.transactions[i].num_output:
                    txn_fee -= block.transactions[i].output_txn[j].value
                    file.write("%s, %d," % (block.transactions[i].output_txn[j].public_key.encode('hex'),
                                             block.transactions[i].output_txn[j].value))
                else:
                    file.write(",,")

                # write down transaction fee
                if j == count-1 and txn_fee != -1:
                    file.write("%d"%txn_fee)

                file.write("\n")

def varint(data, pos):
    # modified based on: https://github.com/toidi/pyblockchain/blob/master/blockchain/block.py#L16

    """The raw transaction format and several peer-to-peer network messages use
    a type of variable-length integer to indicate the number of bytes in a
    following piece of data.

    Reference:
    https://bitcoin.org/en/developer-reference#compactsize-unsigned-integers

    """
    # variable length integer
    # 1 byte unsigned int8
    value, = struct.unpack_from('<B', data,offset=pos)
    pos += struct.calcsize('<B')

    if value < 0xfd:
        pass
    elif value == 0xfd:
        # 0xfd followed by the number as uint16_t
        value, = struct.unpack_from('<H', data, offset=pos)
        pos += struct.calcsize('<H')
    elif value == 0xfe:
        # 0xfe followed by the number as uint32_t
        value, = struct.unpack_from('<I', data, offset=pos)
        pos += struct.calcsize('<I')
    elif value == 255:
        # 0xff followed by the number as uint64_t
        value, = struct.unpack_from('<Q', data, offset=pos)
        pos += struct.calcsize('<Q')
    return value, pos

if __name__ == '__main__':
    from sys import argv


    if len(argv) > 3:
        print "Too many args! Please only give the directory root!"
    else:

        repo = argv[1]
        path = argv[2]
        print ("Will delete all existing files under %s/blocks, %s/utxo_db, %s/processed_blocks, %s/waiting_blocks. Take care! ;( " % (path,path,path,path))
        if not argv[1].endswith('/'):
            repo +='/'
        if os.path.exists(path + '/blocks'):
            shutil.rmtree(path + '/blocks')
        if os.path.exists(path + '/utxo_db'):
            shutil.rmtree(path + '/utxo_db')
        if os.path.exists(path + '/processed_blocks'):
            shutil.rmtree(path + '/processed_blocks')
        if os.path.exists(path + '/waiting_blocks'):
            shutil.rmtree(path + '/waiting_blocks')
        os.mkdir(path + '/blocks')

        # db for unspent transactions
        utxo_db = plyvel.DB(path + '/utxo_db', create_if_missing=True)

        # db for processed blocks
        # key: block hash, value: '1'
        processed_blocks_db = plyvel.DB(path + '/processed_blocks', create_if_missing=True)
        genesis_prev_hash = '0000000000000000000000000000000000000000000000000000000000000000'
        if processed_blocks_db.get(genesis_prev_hash) is None:  # put genesis block previous hash
            processed_blocks_db.put(genesis_prev_hash, bytes(1))

        # db for waiting blocks
        # key: (previous) block hash, value: list of hash of blocks that points to previous block hash
        waiting_blocks_db = plyvel.DB(path + '/waiting_blocks', create_if_missing=True)

        log = open(path+'/log','a+')

        p = Parser()
        p.parser_repo(repo)
