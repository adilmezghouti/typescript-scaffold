import {AccountType, IEncryption, IStorage, NetworkEnum, StateType} from "@liquality/core/dist/types";
import {Config} from "@liquality/core/dist/config";
import Wallet from "@liquality/core/dist/wallet";
import {LocalStorage} from 'node-localstorage'
import {AES, enc as Enc, lib as Lib} from 'crypto-js'
import _pbkdf2 from 'pbkdf2'
import {assets as cryptoassets} from '@liquality/cryptoassets'
import {SendOptions} from "@liquality/types";
import BigNumber from 'bignumber.js'
import dotenv, {config} from 'dotenv'

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
    // const keySalt = Enc.Hex.stringify(Lib.WordArray.random(16))
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
    // return Promise.resolve("");
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
  //-------------------------1. CREATING AN INSTANCE OF THE WALLET--------------------------------------------------------
  const excludedProps: Array<keyof StateType> = ['key', 'wallets', 'unlockedAt']
  const storageManager = new StorageManager('@liquality-storage', excludedProps)
  const encryptionManager = new EncryptionManager()
  const config = new Config(envConfig.INFURA_API_KEY)
  const wallet = new Wallet(storageManager, encryptionManager, config)

  //-------------------------2. REGISTER THE NEEDED CALLBACKS--------------------------------------------------------
  wallet.on('onTransactionUpdate', (transaction) => {
    console.log(transaction)
  })
  wallet.subscribe((account: AccountType) => {
    console.log(account)
  })

  //-------------------------3. BUILD/POPULATE THE WALLET--------------------------------------------------------
  await wallet.init(envConfig.PASSWORD, envConfig.MNEMONIC, true)
  await wallet.addAccounts(NetworkEnum.Testnet)

  //-------------------------4. SEND SOME ETH--------------------------------------------------------
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
  const sendResponse = await assets[0].transmit(options)
  console.log('sendResponse: ', sendResponse)

  //-------------------------5. SWAP ETH FOR BTC--------------------------------------------------------

  return true;
}

buildWallet()
