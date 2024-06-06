from argparse import ArgumentParser

def xor_crypt(enc_data, key):
    dec_bytes = list()
    idx = 0
    key_len = len(key)
    for i in range(len(enc_data)):
        dec_bytes.append(((enc_data[i] ^ ord(key[idx]))) & 0xFF)
        idx = (idx + ord(key[idx])) % key_len
        if idx == 0:
            idx = key_len -1

    dec_data = ''.join(chr(c) for c in dec_bytes).encode('latin-1')
    return dec_data

def get_payload(enc_file, marker_file, out_file):
    marker = open(marker_file, 'rb').read()
    enc_data = open(enc_file, 'rb').read()

    # modify marker
    l = len(marker)
    mod_key = ''
    for c in marker:
        k = c ^ l
        l -= 1
        mod_key += chr(k)
    
    blobs = enc_data.split(marker)
    
    darkgate_enc_final_payload = blobs[1]
    darkgate_payload = xor_crypt(darkgate_enc_final_payload, mod_key)
        
    open(out_file, 'wb').write(darkgate_payload)
    print("\nSaved to {}".format(out_file))

def main():
    # Add arguments
    parser = ArgumentParser(description="Get final DarkGate payload!")
    parser.add_argument("-i", "--input_file", dest='input_file', metavar='INPUT_FILE', type=str, required=True, help="Please specify extracted AutoIt binary file!")
    parser.add_argument("-m", "--marker_file", dest='marker_file', metavar='MARKER_FILE', type=str, required=True, help="Please specify marker file!")
    parser.add_argument("-o", "--output_file", dest='output_file', metavar='OUTPUT_FILE', type=str, required=True, help="Write decrypted payload to output file")
    
    # Parse arguments
    args = parser.parse_args()
    get_payload(args.input_file, args.marker_file, args.output_file)

if __name__ == "__main__":
    main()