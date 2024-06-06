from argparse import ArgumentParser
import sys
import re

# Regular expression pattern to match encoded string
pattern_1 = r"\$a\[0x[0-9a-fA-F]{1,2}].*"
# Regular expression pattern to match hex codes
pattern_2 = r"0x[0-9a-fA-F]{1,2}"

# Define a dictionary to map num to characters
char_map = {0: '(', 1: 'n', 2: 'q', 3: ']', 4: 'N', 5: '*', 6: '0', 7: 'C', 8: 'V', 9: '3', 10: '&', 
            11: 'R', 12: 'e', 13: 'M', 14: 'O', 15: 't', 16: 'J', 17: '}', 18: 'U', 19: 'a', 20: 'D', 
            21: '{', 22: 'W', 23: ' ', 24: 'Z', 25: 'x', 26: 'b', 27: '8', 28: 'u', 29: 'l', 30: 'd', 
            31: 'Y', 32: '"', 33: 'S', 34: 'K', 35: '2', 36: 'T', 37: '1', 38: 'r', 39: 's', 40: 'p', 
            41: 'j', 42: '$', 43: 'o', 44: 'I', 45: 'F', 46: 'f', 47: 'G', 48: 'B', 49: '=', 50: 'Q', 
            51: 'L', 52: '6', 53: '5', 54: '.', 55: 'H', 56: 'c', 57: 'i', 58: '9', 59: 'w', 60: 'z', 
            61: ')', 62: 'E', 63: 'm', 64: '4', 65: 'g', 66: 'h', 67: 'A', 68: 'y', 69: ',', 70: 'k', 
            71: '7', 72: '[', 73: 'X', 74: 'v', 75: 'P'}

def mapping_char(listCharCode):
    message = ""
    for num in listCharCode:
        message += char_map.get(num)    
    # return the final message
    return message

def extract_index_from_str(text):
    # Find all matches of the regex pattern
    matches = re.findall(pattern_2, text)
    
    # Convert hex codes to integers
    idxArr = [int(hex_code, 16) for hex_code in matches]
    
    return idxArr

def main():
    parser = ArgumentParser(description="Deobfuscating DarkGate AutoIt script!!")
    parser.add_argument("-i", "--input_file", dest='input_file', metavar='INPUT_FILE', type=str, required=True, help="Please specify obfuscated script")
    parser.add_argument("-o", "--output_file", dest='output_file', metavar='OUTPUT_FILE', type=str, required=True, help="Write deobfuscated script to output file")
    
    args = parser.parse_args()
    
    try:
        fin = open(args.input_file, "r")
    except IOError as e:
        print("Could not open file %s - %s" % (args.input_file, e))
        return 1

    in_lines = fin.readlines()
    fin.close()

    out_lines = []    
    for line in in_lines:       
        matched_str = re.search(pattern_1, line)
        if matched_str:
            strEncoded = matched_str.group(0)
            idxArray = extract_index_from_str(strEncoded)
            strDecoded = mapping_char(idxArray)
            line = line.replace(strEncoded,strDecoded)
    
        out_lines.append(line)

    if out_lines:
        try:
            fout = open(args.output_file, "w+")
        except IOError as e:
            print("Coult not write to file %s - %s" % (args.output_file, e))
            fout = sys.stdout

        for line in out_lines:
            fout.write(line)
        fout.close()

        print("Deobfuscating done :)")
        return  0   # 0 = EXIT_SUCESS
    return 1    # 1 is EXIT_FAILURE

if __name__ == "__main__":
    sys.exit(main())