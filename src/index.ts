const http = require('http');
import {
  AccountType,
  IAccount,
  IEncryption,
  IStorage,
  NetworkEnum,
  StateType, SwapPayloadType,
  SwapProvidersEnum
} from "@liquality/core/dist/types";
import {Config} from "@liquality/core/dist/config";
import Wallet from "@liquality/core/dist/wallet";
import {LocalStorage} from 'node-localstorage'
import {AES, enc as Enc, lib as Lib} from 'crypto-js'
import _pbkdf2 from 'pbkdf2'
import {assets as cryptoassets, currencyToUnit} from '@liquality/cryptoassets'
import {SendOptions} from "@liquality/types";
import BigNumber from 'bignumber.js'
import dotenv from 'dotenv'


//-------------------------1. PROVIDE IMPLEMENTATIONS FOR THE CLASSES THAT ARE PLATFORM SPECIFIC -----------------------
const PBKDF2_ITERATIONS = 1000000
const PBKDF2_LENGTH = 32
const PBKDF2_DIGEST = 'sha256'
const envConfig = dotenv.config().parsed

interface CipherJsonType {
  ct: string
  iv?: string
  s?: string
}


class EncryptionManager implements IEncryption {

  public async encrypt(value: string, keySalt: string, password: string): Promise<string> {
    const derivedKey = await this.pbkdf2(password, keySalt)
    const rawEncryptedValue = AES.encrypt(value, derivedKey)
    return Promise.resolve(this.JsonFormatter.stringify(rawEncryptedValue));
  }

  public async decrypt(encrypted: string, keySalt: string, password: string): Promise<string> {
    if (!keySalt) {
      return ''
    }

    const encryptedValue = this.JsonFormatter.parse(encrypted)
    try {
      const derivedKey = await this.pbkdf2(password, keySalt)
      const decryptedValue = AES.decrypt(encryptedValue, derivedKey)
      return decryptedValue.toString(Enc.Utf8)
    } catch (e) {
      return ''
    }
  }



  public generateSalt(byteCount: number): string {
    return "";
  }

  public async pbkdf2(password: string, salt: string): Promise<string> {
    return new Promise((resolve, reject) => {
      _pbkdf2.pbkdf2(
          password,
          salt,
          PBKDF2_ITERATIONS,
          PBKDF2_LENGTH,
          PBKDF2_DIGEST,
          (err, derivedKey) => {
            if (err) reject(err)
            else resolve(Buffer.from(derivedKey).toString('hex'))
          }
      )
    })
  }

  private JsonFormatter = {
    stringify(cipherParams: Lib.CipherParams) {
      const jsonObj: CipherJsonType = {
        ct: cipherParams.ciphertext.toString(Enc.Base64),
      }

      if (cipherParams.iv) {
        jsonObj.iv = cipherParams.iv.toString()
      }

      if (cipherParams.salt) {
        jsonObj.s = cipherParams.salt.toString()
      }

      return JSON.stringify(jsonObj)
    },

    parse(jsonStr: string) {
      const jsonObj = JSON.parse(jsonStr)

      const cipherParams = Lib.CipherParams.create({
        ciphertext: Enc.Base64.parse(jsonObj.ct),
      })

      if (jsonObj.iv) {
        cipherParams.iv = Enc.Hex.parse(jsonObj.iv)
      }

      if (jsonObj.s) {
        cipherParams.salt = Enc.Hex.parse(jsonObj.s)
      }

      return cipherParams
    },
  }

}

class StorageManager implements IStorage<StateType> {
  private excludedProps: Array<keyof StateType>
  private storageKey: string
  private _localStorage: LocalStorage

  constructor(storageKey: string, excludedProps: Array<keyof StateType>) {
    this.storageKey = storageKey
    this.excludedProps = excludedProps
    this._localStorage = new LocalStorage(storageKey)
  }

  read(): Promise<StateType> {
    const state = this._localStorage.getItem(this.storageKey)
    return Promise.resolve(JSON.parse(state || '') as StateType);
  }

  write(data: StateType): Promise<boolean | Error> {
    if (!data || Object.keys(data).length === 0) {
      return Promise.reject(new Error('Empty data'))
    }
    try {
      this.excludedProps.forEach((prop: keyof StateType) => {
        if (data.hasOwnProperty(prop)) {
          delete data[prop]
        }
      })
      if (Object.keys(data).length > 0) {
        this._localStorage.setItem(this.storageKey, JSON.stringify(data))
        return Promise.resolve(true)
      } else {
        return Promise.reject(Error('Can not write sensitive data'))
      }
    } catch (e) {
      return Promise.reject(false)
    }
  }

}


export default async function buildWallet() {
  //-------------------------2. CREATING AN INSTANCE OF THE WALLET--------------------------------------------------------
  const excludedProps: Array<keyof StateType> = ['key', 'wallets', 'unlockedAt']
  const storageManager = new StorageManager('@liquality-storage', excludedProps)
  const encryptionManager = new EncryptionManager()
  const config = new Config(envConfig.INFURA_API_KEY)
  const wallet = new Wallet(storageManager, encryptionManager, config)


  //-------------------------3. REGISTER THE NEEDED CALLBACKS--------------------------------------------------------
  wallet.on('onTransactionUpdate', (transaction) => {
    console.log(transaction)
  })
  wallet.subscribe((account: AccountType) => {
    console.log(account)
  })


  //-------------------------4. BUILD/POPULATE THE WALLET--------------------------------------------------------
  await wallet.init(envConfig.PASSWORD, envConfig.MNEMONIC, true)
  await wallet.addAccounts(NetworkEnum.Testnet)


  //-------------------------5. SEND SOME ETH--------------------------------------------------------
  const account = await wallet.getAccount(
      cryptoassets['ETH'].chain,
      NetworkEnum.Testnet,
  )
  const assets = await account.getAssets()
  const options: SendOptions = {
    to: '0x1f49F22879C323514Fd6fe069A20d381E432Eb11',
    value: new BigNumber(3000000000000000), //0.003 ETH
    fee: 3.1
  }
  const sendResponse = await assets[0].transmit(options).catch(error => {
    console.log('error: ', error.message)
  })
  console.log('sendResponse: ', sendResponse)


  //-------------------------6. SWAP ETH FOR BTC--------------------------------------------------------
  //TODO prompt the user in the console to enter these values
  const fromAsset = 'ETH'
  const toAsset = 'BTC'
  const fromAmount = new BigNumber(0.004)
  const toAmount = new BigNumber(0.0004)
  const fromNetworkFee = new BigNumber(2.99)
  const toNetworkFee = new BigNumber(1)

  const fromAccount: IAccount = wallet.getAccount(cryptoassets[fromAsset].chain, NetworkEnum.Testnet)
  const toAccount: IAccount = wallet.getAccount(cryptoassets[toAsset].chain, NetworkEnum.Testnet)

  if (!fromAccount || !toAccount) {
    console.error('Make sure to provide two accounts to perform a swap')
  }

  const swapProvider = wallet.getSwapProvider(SwapProvidersEnum.LIQUALITY)
  if (!swapProvider) {
    console.error('Failed to perform the swap')
  }

  const quote: Partial<SwapPayloadType> = {
    from: fromAsset,
    to: toAsset,
    fromAmount: new BigNumber(
        currencyToUnit(cryptoassets[fromAsset], fromAmount.toNumber()),
    ),
    toAmount: new BigNumber(
        currencyToUnit(cryptoassets[toAsset], toAmount.toNumber()),
    ),
    fee: fromNetworkFee.toNumber(),
    claimFee: toNetworkFee.toNumber(),
  }

  const swapResponse = await swapProvider
      .performSwap(fromAccount, toAccount, quote)
      .catch((error: any) => {
        console.error(`Failed to perform the swap: ${error}`)
      })

  console.log(`SwapResponse: ${swapResponse}`)
}


const hostname = '127.0.0.1';
const port = 3000;

//TODO Use the console mode instead to allow user interactions
const server = http.createServer((req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello World');
});

server.listen(port, hostname, async () => {
  console.log(`Server running at http://${hostname}:${port}/`);
  await buildWallet()
});
