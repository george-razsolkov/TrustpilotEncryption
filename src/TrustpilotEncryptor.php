<?php
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
include ('AES.php');

class TrustpilotEncryptor
{
    protected $message;
    protected $key;
    protected $hash_key;
    protected $mode;
    protected $blocksize;

    public function __construct($message, $key, $hash_key) {
        $this->message = $message;
        $this->key = $key;
        $this->hash_key = $hash_key;
        $this->mode = null;
        $this->blocksize = null;
    }

    protected function setMessage($message) {
        $this->message = $message;
    }

    protected function getMessage() {
        return $this->message;
    }
    
    protected function setMode($mode) {
       
        if($mode !== 'cbc' && $mode !== 'ecb'  && $mode !== 'ctr' && $mode !== 'ocb'
            && $mode !== 'cfb') {
            throw new Exception("Invalid mode for encrypting: " . __FILE__ .'>'. __CLASS__ . '>'. __LINE__ );
        }
        $this->mode = $mode;
    }

    protected function setBlocksize($blocksize) {
        $this->blocksize = $blocksize;
    }

    /*
     * param $mode should be cbc,ebc  etc
     */

    public function trustpilot_encrypt($blocksize, $mode) {

        $this->setMode($mode);
        $this->setBlocksize($blocksize);
        $message = $this->utf8_encode_message($this->message);

        $encrypt_key = base64_decode($this->key);

        $hash_key = base64_decode($this->hash_key);

        // 16 is IV blocksize for PKCS7
        $pad = 16 - (strlen($message) % 16);

        $message .= str_repeat(chr($pad), $pad);
        
        $cipher = new AES($message, $encrypt_key, $blocksize, $mode);
        //setting the vector to 16 blank spaces for test
        //$cipher->setIV("                ");
        $encrypted_message = $cipher->encrypt(); //returns base64 encoded string
        $vectorMessage = $cipher->getIV().base64_decode($encrypted_message);
        $msg_hash = hash_hmac('sha256', $vectorMessage, $hash_key, true);

        $encrypted = base64_encode($vectorMessage.$msg_hash);
        $this->setMessage($encrypted);
        return $this->message;
    }
    /*
     * The decoded message is base64_encoded already
     * get message as array of bytes
     * remove IV from the front and hash from the back.
     * decode the message.
     */

    public function trustpilot_decrypt() {
        var_dump('decoding ' . $this->message);
        $decoded_hash_key = base64_decode($this->hash_key);
        $decode_encrypt_key = base64_decode($this->key);
        $decoded_message = base64_decode($this->message);

        $arrayOfBytes = unpack('C*', $decoded_message);

        $messageArrayOfBytes = array_slice($arrayOfBytes, 16,
            count($arrayOfBytes) - (32 + 16));
        $realMessage = implode(array_map("chr", $messageArrayOfBytes));

        $iv = array_slice($arrayOfBytes, 0, 16);
        //geting the iv vector
        $ivString = implode(array_map("chr", $iv));
        $cipher = new AES(base64_encode($realMessage), $decode_encrypt_key, $this->blocksize, $this->mode);
        $cipher->setIV($ivString);
       
        $message = $cipher->decrypt();
        
        return utf8_encode($message);
    }

    protected function utf8_encode_message($input) {
        if (is_string($input)) {
            $input = utf8_encode($input);
        } else if (is_array($input)) {
            foreach ($input as &$value) {
                utf8_encode_deep($value);
            }

            unset($value);
        } else if (is_object($input)) {
            $vars = array_keys(get_object_vars($input));

            foreach ($vars as $var) {
                utf8_encode_deep($input->$var);
            }
        }

        return $input;
    }
}







