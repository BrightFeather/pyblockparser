from blockparser_checkorder import *

# file = 'blk00000.dat'
# p = Parser()
# p.parse_file(file)
path = '.'

if os.path.exists(path + '/blocks'):
    shutil.rmtree(path + '/blocks')
if os.path.exists(path + '/utxo_db'):
    shutil.rmtree(path + '/utxo_db')
if os.path.exists(path + '/processed_blocks'):
    shutil.rmtree(path + '/processed_blocks')
if os.path.exists(path + '/waiting_blocks'):
    shutil.rmtree(path + '/waiting_blocks')
os.mkdir(path + '/blocks')

p = Parser()
p.parser_repo('.')