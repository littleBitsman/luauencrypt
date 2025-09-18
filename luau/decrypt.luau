--!strict

local MAGIC = "LUAUBYTX"
local AEAD_XCHACHA20 = 1
local NONCE_LEN = 24
local TAG_LEN = 16

local AEAD = require("./AEAD")

local function decrypt_luaucxv1(buf: buffer, key: buffer): { additional_data: buffer, data: buffer }?
    local offset = 0
    local function read(bytes: number): number
        local pos = offset
        offset += bytes
        return pos
    end

    local magic = buffer.readstring(buf, read(#MAGIC), #MAGIC)
    if magic ~= MAGIC then
        error("Invalid bytecode")
    end

    local ver = buffer.readu8(buf, read(1))
    if ver ~= 1 then
        error("Unsupported version")
    end
    print(ver)

    local aead_id = buffer.readu8(buf, read(1))
    if aead_id ~= AEAD_XCHACHA20 then
        error("Unsupported AEAD")
    end
    print(aead_id)

    local key_id = buffer.readu16(buf, read(2))
    local ad_len = buffer.readu32(buf, read(4))
    local ct_len = buffer.readu32(buf, read(4))
    print(key_id, ad_len, ct_len)

    local ad = buffer.create(ad_len)
    buffer.copy(ad, 0, buf, read(ad_len), ad_len)
    print(buffer.tostring(ad))

    local nonce = buffer.create(NONCE_LEN)
    buffer.copy(nonce, 0, buf, read(NONCE_LEN), NONCE_LEN)

    local ct = buffer.create(ct_len)
    buffer.copy(ct, 0, buf, read(ct_len), ct_len)
    
    local tag = buffer.create(TAG_LEN)
    buffer.copy(tag, 0, buf, read(TAG_LEN), TAG_LEN)
    
    local out = AEAD.Decrypt(ct, key, nonce, tag, ad, nil, true)

    if not out then return end

    return {
        additional_data = ad,
        data = out
    }
end

--[[ -- was testing with this

local fs = require("@lune/fs")

local key = buffer.fromstring(fs.readFile("example_key"))
local bytecode = buffer.fromstring(fs.readFile("example.luauc"))
local aad = buffer.fromstring("v1")
local nonce = buffer.fromstring(fs.readFile("nonce"))
local encrypted, tag = AEAD.Encrypt(bytecode, key, nonce, aad, nil, true)
local len = 4 + 1 + 1 + 2 + 1 + 3 + (4 * 3) + buffer.len(aad) + NONCE_LEN + buffer.len(encrypted) + TAG_LEN
local buf = buffer.create(len)
local offset = 0
local function write(bytes: number)
    local pos = offset
    offset += bytes
    return pos
end
buffer.writestring(buf, write(#MAGIC), MAGIC)
buffer.writeu8(buf, write(1), 1)
buffer.writeu8(buf, write(1), AEAD_XCHACHA20)
buffer.writeu16(buf, write(2), 1)
buffer.writeu32(buf, write(4), buffer.len(aad))
buffer.writeu32(buf, write(4), buffer.len(encrypted))
buffer.copy(buf, write(buffer.len(aad)), aad, 0)
buffer.copy(buf, write(NONCE_LEN), nonce, 0)
buffer.copy(buf, write(buffer.len(encrypted)), encrypted, 0)
buffer.copy(buf, write(TAG_LEN), tag, 0)
fs.writeFile("encrypted_luau.luaucx", buffer.tostring(buf))

buf = buffer.fromstring(fs.readFile("encrypted_rust.luaucx"))
local result = assert(decrypt_luaucxv1(buf, key), "failed to decrypt")
fs.writeFile("decrypted_from_rustenc.luauc", buffer.tostring(result.data))
local other = fs.readFile("example.luauc")
print(other == buffer.tostring(result.data))
]]