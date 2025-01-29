from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39WordsNum, Bip44Changes, Bip49, Bip49Coins, Bip44, Bip44Coins, Bip84, Bip84Coins
from multiprocessing import Pool, cpu_count

#arp = open('addresses_bip4410.txt', 'a')
#arp = open('addresses_bip4910.txt', 'a')
arp = open('addresses_bip8410.txt', 'a')

def generatemenemonic(listofmenmonic):

    mnemonic = listofmenmonic
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip84_mst_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
    #bip49_mst_ctx = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
    #bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    bip84_acc_ctx = bip84_mst_ctx.Purpose().Coin().Account(0)
    bip84_chg_ctx = bip84_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
   # bip49_acc_ctx = bip49_mst_ctx.Purpose().Coin().Account(0)
   # bip49_chg_ctx = bip49_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
  #  bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
   # bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    #bip44_addr_ctx = bip44_chg_ctx.AddressIndex(0)
   # bip49_addr_ctx = bip49_chg_ctx.AddressIndex(0)
    bip84_addr_ctx = bip84_chg_ctx.AddressIndex(0)
  #  arp.write("%s \n" % bip44_addr_ctx.PublicKey().ToAddress())
   # arp.write("%s \n" % bip49_addr_ctx.PublicKey().ToAddress())
    arp.write("%s \n" % bip84_addr_ctx.PublicKey().ToAddress())


if __name__ == "__main__":
    listofmenmonic = []
    with open('seed10.txt') as f:
        for line in f:
            mnemonic = line.strip()
            listofmenmonic.append(mnemonic)

    cpustotal = cpu_count()-1
    pool = Pool(cpustotal)
    print("Starting Address Generator on " +str(cpustotal)+ " CPU's")
    results = pool.map(generatemenemonic, listofmenmonic)
    pool.close()
    pool.join()
