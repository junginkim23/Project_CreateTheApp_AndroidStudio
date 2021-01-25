package com.example.mobileserver.Server_Code;

import android.os.Handler;
import android.os.StrictMode;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.EditText;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Timer;
import java.util.TimerTask;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import android.util.Base64;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.security.spec.InvalidKeySpecException;
import java.lang.Throwable;
//p2p import
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;

import com.example.mobileserver.R;


public class MainActivity extends AppCompatActivity {
    private TextView streamStatus, ServerIP,sendFrame;
    private EditText editText_RTPport;
    private Timer mtimer1,mtimer2;
    private Handler handler1,handler2;
    private boolean status_RTPport_enter=false;

    //RTP variables:
    //----------------
    DatagramSocket RTPsocket; //socket to be used to send and receive UDP packets
    DatagramPacket senddp; //UDP packet containing the video frames

    InetAddress ClientIPAddr; //Client IP address
    int RTP_dest_port = 0; //destination port for RTP packets  (given by the RTSP Client)

    //Video variables:
    //----------------
    int imagenb = 0; //image nb of the image currently transmitted
    VideoStream video; //VideoStream object used to access video frames
    static int MJPEG_TYPE = 26; //RTP payload type for MJPEG video
    static int FRAME_PERIOD = 100; //Frame period of the video to stream, in ms
    static int VIDEO_LENGTH = 500; //length of the video in frames

    //Timer timer; //timer used to send the images at the video frame rate
    byte[] buf; //buffer used to store the images to send to the client
    // byte[] EN_buf;
    // byte[] EN_buf2;
    //RTSP variables
    //----------------
    //rtsp states
    private int EN_STATE;
    final static int CLEAR = 0;
    final static int DHON = 1;
    final static int RSAON = 2;
    final static int INIT = 0;
    final static int READY = 1;
    final static int PLAYING = 2;
    final static int STOP = 7;
    //rtsp message types
    final static int SETUP = 3;
    final static int PLAY = 4;
    final static int PAUSE = 5;
    final static int TEARDOWN = 6;
    final static int DHSETUP = 8;
    final static int RSASETUP = 9;
    static int state; //RTSP Server state == INIT or READY or PLAY
    Socket RTSPsocket; //socket used to send/receive RTSP messages
    private ServerSocket listenSocket;
    //input and output stream filters
    static BufferedReader RTSPBufferedReader;
    static BufferedWriter RTSPBufferedWriter;
    static String VideoFileName; //video file requested from the client
    static int RTSP_ID = 123456; //ID of the RTSP session
    int RTSPSeqNb = 0; //Sequence number of RTSP messages within the session
    static String s_RTSP_ID ; //ID of the RTSP session
    static String s_RTSPSeqNb; //Sequence number of RTSP messages within the session
    private String str_keysize;
    private String str_prime;
    private String str_alpha;
    private String str_A_Pubkey;
    private String str_B_shared_key;
    private String str_M_public_key;
    private String str_Rec_Public_Key;
    static PublicKey Client_RSAPublicKey;
    final static String CRLF = "\r\n";
    private Thread thread_serverStart;
    private  boolean status_mtimer2 =false,status_mtimer = true,status_mtimer1_cancel = true,status_mtimer2_cancel = false,status_close=false;
//p2p chat
private Button startButton;
    private EditText inputMessage,editPeerIP;
    private InetAddress PeerIP2;
    private InetAddress PeerIP1;
    private boolean Callee = false;
    private TextView receive_message;
    private int SEND_PORT = 7777;
    private int RECV_PORT = 8888;
    private String MessageInput;
    private ArrayAdapter<String> mConversationArrayAdapter;
    private ListView   mConversationView;
    private DatagramSocket send_socket;
    TextView OwnIP;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

        setContentView(R.layout.activity_main);
        // editText_RTPport = (EditText) findViewById(R.id.editText_RTPport);
        streamStatus = (TextView) findViewById(R.id.textView_streamStatus);
        sendFrame = (TextView) findViewById(R.id.textView_sendFrame);
        // ServerIP = (TextView) findViewById(R.id.ServerIP);//add
        //ServerIP.setText("Listening to: " + getIpAddress()+ "\n" + "RTSPport = 18888");//add
        mtimer1 = new Timer();
        handler1 = new Handler();
        handler2 = new Handler();
        buf = new byte[15000];

        status_close = false;
        serverStart();
        OwnIP = (TextView) findViewById(R.id.OwnIP);
        OwnIP.setText(getIpAddress());
        editPeerIP = (EditText)findViewById(R.id.editText_ServerIP);
        startButton = (Button) findViewById (R.id.button_play);
        inputMessage = (EditText) findViewById (R.id.input_message);
        receive_message = (TextView) findViewById (R.id.receive_message);
        mConversationArrayAdapter = new ArrayAdapter<String>(this, R.layout.message);
        mConversationView = (ListView) findViewById(R.id.listView1);
        mConversationView.setAdapter(mConversationArrayAdapter);


        startButton.setOnClickListener(startP2PSend);



        Thread startReceiveThread = new Thread(new StartReceiveThread());
        startReceiveThread.start();

        try {
            send_socket = new DatagramSocket(SEND_PORT);
        } catch (SocketException e) {
            Log.e("VR", "Sender SocketException");

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    private final OnClickListener startP2PSend = new OnClickListener() {

        @Override
        public void onClick(View arg0) {
            Log.d("VR", "Click OK");
            startP2PSending();

        }

    };

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


    public void startP2PSending() {

        Thread startP2PSendingThread = new Thread (new Runnable() {

            @Override
            public void run() {

                try {
                    MessageInput = inputMessage.getText().toString();
                    byte MessageInputByte[]=new byte[1024];


                    if(Callee == true){
                        PeerIP1 = PeerIP2;
                    }
                    else
                    {
                        PeerIP1 =  InetAddress.getByName(editPeerIP.getText().toString());
                    }

                    MessageInputByte= rc4_encrypt(MessageInput.getBytes(),str_B_shared_key);

                    final InetAddress peerIP = InetAddress.getByName(editPeerIP.getText().toString());

                    DatagramPacket send_packet = new DatagramPacket(MessageInput.getBytes(), MessageInput.length(),PeerIP1,RECV_PORT);

                    send_socket.send(send_packet);
                    Log.d("VR", "Packet Send");

                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {


                            mConversationArrayAdapter.add("Sending from " + getIpAddress().trim() + " : " + inputMessage.getText().toString());
                        }
                    });





                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {

                            inputMessage.setText("");

                        }
                    });
                    //}

                } catch (SocketException e) {
                    Log.e("VR", "Sender SocketException");

                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                catch (NoSuchAlgorithmException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (InvalidAlgorithmParameterException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                catch (Throwable e) {
                    e.printStackTrace();
                }


            }

        });
        startP2PSendingThread.start();
    }
    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    private class StartReceiveThread extends Thread {

        DatagramSocket recv_socket;
        byte[] receiveData =new byte[1024];

        public void run() {

            try {

                recv_socket = new DatagramSocket(RECV_PORT);

                Log.d("VR", "Receiver Socket Created");

                while (true) {
                    ss=new ServerSocket(SRCV_PORT);
                    socket=ss.accept();
                    is=socket.getInputStream();
                    dis=new DataInputStream(is);
                    int a=dis.readInt();
                    Log.d("VR", "CHECTK A"+a);
                    socket.close();
                    DatagramPacket recv_packet = new DatagramPacket(receiveData, receiveData.length);
                    Log.d("VR", "Packet Received1"+recv_packet);
                    recv_socket.receive(recv_packet);
                    Log.d("VR", "Packet Received2");
                    if (EN_STATE == DHON) {
                        //받은 패킷을 복호화 하는 거 만들어야 함.<<<수정한 부분>>>>>
                        receiveDataByte = rc4_decrypt(recv_packet.getData(), dh_shared_secret);
                    }
                    InetAddress sourceHost = recv_packet.getAddress();
                    PeerIP2 = sourceHost;
                    for(i=0,j=0;i<a;i++,j++){
                        ByteToInput[j] = receiveDataByte[i];
                    }
                    receive_data = new String(ByteToInput);
                    Callee = true;
                    final String sourceIP = sourceHost.getHostName();
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            mConversationArrayAdapter.add("Message from " + sourceIP + " : " + receive_data);
                        }
                    });

                }
                }

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }


        }


    }

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    private String getIpAddress() {
        String ip = "";
        try {
            Enumeration<NetworkInterface> enumNetworkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (enumNetworkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = enumNetworkInterfaces.nextElement();
                Enumeration<InetAddress> enumInetAddress = networkInterface.getInetAddresses();
                while (enumInetAddress.hasMoreElements()) {
                    InetAddress inetAddress = enumInetAddress.nextElement();
                    if (inetAddress.isSiteLocalAddress()) {
                        ip += inetAddress.getHostAddress() + "\n";
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
            ip += "Something Wrong! " + e.toString() + "\n";
        }
        return ip;
    }

    private void serverStart(){

        Runnable run_serverStart = new Runnable() {
            @Override
            public void run() {

                //get RTSP socket port from the command line

                //int RTSPport = Integer.parseInt(editText_RTPport.getText().toString());
                int RTSPport = 18888;



                //Initiate TCP connection with the client for the RTSP session
                try {
                    listenSocket = new ServerSocket(RTSPport);
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            streamStatus.setText("Listening to:   " + getIpAddress());
                        }
                    });
                    RTSPsocket = listenSocket.accept();
                    // listenSocket.close();
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            streamStatus.setText("Connected to Client");
                        }
                    });


                    //Get Client IP address
                    ClientIPAddr = RTSPsocket.getInetAddress();

                    //Initiate RTSPstate
                    state = INIT;

                    //Set input and output stream filters:
                    RTSPBufferedReader = new BufferedReader(new InputStreamReader(RTSPsocket.getInputStream()) );
                    RTSPBufferedWriter = new BufferedWriter(new OutputStreamWriter(RTSPsocket.getOutputStream()) );

                    //mtimer1 = new Timer();
                    // mtimer2 = new Timer();

                }catch (IOException e){

                }
                //Wait for the SETUP message from the client
                int request_type;

                //loop to handle RTSP requests
                while(status_close == false)
                {
                    //parse the request
                    request_type = parse_RTSP_request(); //blocking

                    if (request_type == SETUP) {
                        // done = true;

                        //update RTSP state
                        state = READY;
                        MainActivity.this.runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                streamStatus.setText("New RTSP state: READY");
                            }
                        });
                        System.out.println("New RTSP state: READY");

                        //Send response
                        send_RTSP_response();
                        EN_STATE = CLEAR;

                        //init the VideoStream object:
                        try {
                            video = new VideoStream(VideoFileName);
                        } catch (Exception e) {

                        }

                        //init RTP socket
                        try {
                            RTPsocket = new DatagramSocket();
                        } catch (SocketException e) {

                        }
                    }
                    // request = DHSETUP
                    if (request_type == DHSETUP) {
                        // done = true;

                        //update RTSP state
                        state = READY;
                        MainActivity.this.runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                streamStatus.setText("New RTSP state: DH READY");
                            }
                        });
                        System.out.println("New RTSP state: DH READY");

                        //Send response
                        DH_Process_send_RTSP_response();
                        EN_STATE = DHON;

                        //init the VideoStream object:

                    }
                    // DHSETUP end



                    if ((request_type == PLAY) && (state == READY))
                    {
                        //send back response
                        //Log.d("VR", " before send_RTSP_response()  ");
                        send_RTSP_response();
                        // Log.d("VR", " after send_RTSP_response()  ");
                        // System.exit(0);
                        //start timer
                        if(status_mtimer == true) {
                            timerplay1();
                            status_mtimer1_cancel = true;
                            status_mtimer2_cancel = false;
                        }

                        if(status_mtimer2 == true) {
                            timerplay2();
                            status_mtimer1_cancel = false;
                            status_mtimer2_cancel = true;
                        }


                        // timerplay();
                        //timer.start();
                        //update state
                        state = PLAYING;
                        MainActivity.this.runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                streamStatus.setText("New RTSP state: PLAYING");
                            }
                        });
                        System.out.println("New RTSP state: PLAYING");
                    }
                    else if ((request_type == PAUSE) && (state == PLAYING))
                    {
                        //send back response
                        send_RTSP_response();
                        //stop timer

                        if(status_mtimer1_cancel == true) {
                            mtimer1.cancel();
                            status_mtimer =false;
                            status_mtimer2 =true;
                            mtimer2 = new Timer();
                        }

                        if(status_mtimer2_cancel == true) {
                            mtimer2.cancel();
                            status_mtimer =true;
                            status_mtimer2 =false;
                            mtimer1 = new Timer();
                        }
                        // handler2 = new Handler();

                        //timer.stop();
                        //update state
                        state = READY;
                        System.out.println("New RTSP state: READY");
                    }
                    else if (request_type == TEARDOWN)
                    {
                        state = STOP;
                        //send back response
                        MainActivity.this.runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                streamStatus.setText("New RTSP state: STOP");
                            }
                        });
                        System.out.println("New RTSP state: STOP");
                        send_RTSP_response();
                        //stop timer
                        status_close = true;


                        //  handler1 = new Handler();
                        // handler2 = new Handler();

                        try {
                            Thread.sleep(50);
                            // Log.d("VS", "Thread WAKES UP");
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }


                        //timer.stop();







                        // System.exit(0);
                    }
                }




            }
        };
        thread_serverStart = new Thread(run_serverStart, "run_serverStart");
        thread_serverStart.start();

    }


    //------------------------------------
    //Parse RTSP Request
    //------------------------------------
    private int parse_RTSP_request()
    {
        int request_type = -1;
        try{

            // send dhrequest format
            //RTSPBufferedWriterdh.write(request_type + " " + keysize + " " + S_prime + CRLF);
            // RTSPBufferedWriterdh.flush();
            //write the CSeq line:
            // RTSPBufferedWriterdh.write(S_alpha + " " + S_A_PubKey + CRLF);
            //  RTSPBufferedWriterdh.flush();
            //check if request_type is equal to "SETUP" and in this case write the Transport: line advertising to the server the port used to receive the RTP packets RTP_RCV_PORT

            // RTSPBufferedWriterdh.write("Session: " + RTSPid + CRLF);

            // RTSPBufferedWriterdh.flush();
            //
            Log.d("VR", "waiting for RTSPBufferedReader.readLine() ");
            //parse request line and extract the request_type:
            // RTSPBufferedReader.reset();

            String RequestLine = RTSPBufferedReader.readLine();
            System.out.println(RequestLine);
            StringTokenizer tokens = new StringTokenizer(RequestLine);
            String request_type_string = tokens.nextToken();

            //String SeqNumLine = RTSPBufferedReader.readLine();
            // String LastLine = RTSPBufferedReader.readLine();
            // System.out.println(LastLine);


            //System.out.println("RTSP Server - Received from Client:");
            //System.out.println(RequestLine);
            Log.d("VR", "RequestLine  " + RequestLine);
            // Log.d("VR", "SeqNumLine  "+ SeqNumLine);
            //Log.d("VR", "LastLine  " + LastLine);

            //StringTokenizer tokens = new StringTokenizer(RequestLine);


            //convert to request_type structure:
            if ((new String(request_type_string)).compareTo("SETUP") == 0)
                request_type = SETUP;
            else if ((new String(request_type_string)).compareTo("DHSETUP") == 0)
            {request_type = DHSETUP;
                str_keysize = tokens.nextToken();
                str_prime = tokens.nextToken();}


            else if ((new String(request_type_string)).compareTo("PLAY") == 0)
            { request_type = PLAY;}
            else if ((new String(request_type_string)).compareTo("PAUSE") == 0)
            { request_type = PAUSE;}
            else if ((new String(request_type_string)).compareTo("TEARDOWN") == 0)
            { request_type = TEARDOWN;}
            // else {

            // System.out.println("parse incorrect request type  ");
            //System.exit(0);
            //}

            if (request_type == SETUP)
            {
                //extract VideoFileName from RequestLine
                VideoFileName = tokens.nextToken();
            }

            //parse the SeqNumLine and extract CSeq field
            String SeqNumLine = RTSPBufferedReader.readLine();
            System.out.println(SeqNumLine);
            tokens = new StringTokenizer(SeqNumLine);
            if ((new String(request_type_string)).compareTo("DHSETUP") == 0) {
                tokens.nextToken();
                str_alpha = tokens.nextToken();
            }


            else {
                tokens.nextToken();
                RTSPSeqNb = Integer.parseInt(tokens.nextToken());
            }


            //get LastLine
            String LastLine = RTSPBufferedReader.readLine();
            System.out.println(LastLine);
            //Thread.sleep(200);

            if (request_type == SETUP)
            {
                //extract RTP_dest_port from LastLine
                tokens = new StringTokenizer(LastLine);
                for (int i=0; i<3; i++)

                    tokens.nextToken(); //skip unused stuff
                RTP_dest_port = Integer.parseInt(tokens.nextToken());
            }
            if (request_type == DHSETUP)
            {
                //extract RTP_dest_port from LastLine
                tokens = new StringTokenizer(LastLine);

                tokens.nextToken(); //skip unused stuff
                str_A_Pubkey = tokens.nextToken();
            }
            //else LastLine will be the SessionId line ... do not check for now.
        }
        catch(Exception ex)
        {
            System.out.println("Exception caught: "+ex);
            //System.exit(0);
        }

        return(request_type);
    }

    //------------------------------------
    //Send RTSP Response
    //------------------------------------
    private void send_RTSP_response()
    {
        try{

            s_RTSP_ID = String.valueOf(RTSP_ID);
            s_RTSPSeqNb = String.valueOf(RTSPSeqNb);
            RTSPBufferedWriter.write("RTSP/1.0 200 OK"+'\n');
            RTSPBufferedWriter.write("CSeq: "+s_RTSPSeqNb+'\n');
            RTSPBufferedWriter.write("Session: "+s_RTSP_ID+'\n');
            RTSPBufferedWriter.flush();
            //System.out.println("RTSP Server - Sent response to Client.");
        }
        catch(Exception ex)
        {
            System.out.println("Exception caught: "+ex);
            // System.exit(0);
        }
    }

    //------------------------------------
    //Send DH RTSP Response
    //------------------------------------
    private void DH_Process_send_RTSP_response()
    {

        try{
            BigInteger prime = new BigInteger(str_prime);
            BigInteger alpha = new BigInteger(str_alpha);
            KeyPairGenerator bkpg = KeyPairGenerator.getInstance("DH");
            DHParameterSpec param = new DHParameterSpec(prime, alpha);
            bkpg.initialize(param);
            KeyPair B_kp = bkpg.generateKeyPair(); //public key (Yb) and private key (Xb) of B
            Log.d("VR", "Keypair OK");
            byte[] publicBytes = Base64.decode(str_A_Pubkey.getBytes(), Base64.NO_WRAP);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey A_publicKey = keyFactory.generatePublic(keySpec);
            final BigInteger B_SharedSecret = getSharedKey(A_publicKey, B_kp.getPrivate());
            str_B_shared_key = B_SharedSecret.toString();
            //send blind key
            Log.d("VS", "S's shared DH key = " + str_B_shared_key);
            final BigInteger B_PubKey = ((DHPublicKey) B_kp.getPublic()).getY();
            final String S_B_PubKey = Base64.encodeToString(B_kp.getPublic().getEncoded(), Base64.NO_WRAP);
            // final String reply_message = "2" + "$$" + S_B_PubKey + "$$1111" +CRLF;

            RTSPBufferedWriter.write("RTSP/1.0 200 OK"+'\n');
            RTSPBufferedWriter.flush();
            RTSPBufferedWriter.write("CSeq: " + S_B_PubKey + '\n');
            RTSPBufferedWriter.flush();
            s_RTSP_ID= String.valueOf(RTSP_ID);
            RTSPBufferedWriter.write("Session: " + s_RTSP_ID + '\n');
            RTSPBufferedWriter.flush();
            Log.d("VR", "after RTSPBufferedWriter.write(Session:  + RTSP_ID + CRLF)  ");
            //System.out.println("RTSP Server - Sent response to Client.");
        }
        catch(Exception ex)
        {
            System.out.println("Exception caught: "+ex);
            // System.exit(0);
        }
    }
    //------------------------------------
    //Send RSA RTSP Response
    //------------------------------------


    private static BigInteger getSharedKey(PublicKey pubKey, PrivateKey privKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(privKey);
        ka.doPhase(pubKey, true);
        byte[] b = ka.generateSecret();
        BigInteger secretKey = new BigInteger(b);
        return secretKey;
    }



    public   byte[] rc4_encrypt(byte[] clearText, String B_shared_key)throws  NoSuchAlgorithmException, InvalidKeyException, Throwable {
        byte[] clearText_;
        byte[] cipherText;
        byte[] returnText = new byte[clearText.length];
        int length=B_shared_key.length();
        if(length>16 && length!=16){
            B_shared_key=B_shared_key.substring(0, 15);
        }
        if(length<16 && length!=16){
            for(int i=0;i<16-length;i++){
                B_shared_key=B_shared_key+"0";
            }
        }

        try {
            Cipher rc4 = Cipher.getInstance("RC4");
            SecretKeySpec rc4Key = new SecretKeySpec(B_shared_key.getBytes(), "RC4");
            rc4.init(Cipher.ENCRYPT_MODE, rc4Key);
            cipherText = rc4.update(clearText);
            int counter = 0;
            while (counter < cipherText.length) {
                returnText[counter] = cipherText[counter];
                counter++;
            }
            return returnText;
        } catch (Exception e) { return null; }
    }

    /*public static byte[] rsa_encrypt(byte[] text, PublicKey key) {
        byte[] cipherText = new byte[text.length];
        Cipher cipher;
        try {

            int counter = 0;
            while (counter < text.length) {
                cipherText[counter] = (byte)text[counter];
                counter++;
            }
            // get an RSA cipher object and print the provider
            cipher = Cipher.getInstance("RSA");
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // cipherText = cipher.doFinal(text.getBytes());
            cipherText = cipher.doFinal(text);
            Log.d("VR", " cipherText = cipher.doFinal(text)");
            //string.getBytes(StandardCharsets.UTF_8)
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    } */



    public void timerplay1()  {

        //init Timer
        // timer = new Timer(FRAME_PERIOD, this);
        // timer.setInitialDelay(0);
        // timer.setCoalesce(true);

        mtimer1.schedule(new TimerTask() {
            @Override
            public void run() {

                handler1.post(new Runnable() {
                    @Override
                    public void run() {
                        //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                        //if the current image nb is less than the length of the video
                        if (imagenb < VIDEO_LENGTH)
                        {
                            //update current imagenb
                            imagenb++;

                            try {
                                //get next frame to send from the video, as well as its size
                                int image_length = video.getnextframe(buf);
                                // encrypt
                                byte[] EN_buf = new byte[buf.length];

                                if(EN_STATE == DHON) {
                                    EN_buf = rc4_encrypt(buf, str_B_shared_key);
                                }

                                //
                                //Builds an RTPpacket object containing the frame
                                RTPpacket rtp_packet = new RTPpacket(MJPEG_TYPE, imagenb, imagenb*FRAME_PERIOD, EN_buf, image_length);

                                //get to total length of the full rtp packet to send
                                int packet_length = rtp_packet.getlength();

                                //retrieve the packet bitstream and store it in an array of bytes
                                byte[] packet_bits = new byte[packet_length];
                                rtp_packet.getpacket(packet_bits);

                                //send the packet as a DatagramPacket over the UDP socket
                                senddp = new DatagramPacket(packet_bits, packet_length, ClientIPAddr, RTP_dest_port);
                                RTPsocket.send(senddp);
                                //Log.d("VR", " RTPsocket.send(senddp)" );
                                //System.exit(0);
                                //System.out.println("Send frame #"+imagenb);
                                //print the header bitstream
                                rtp_packet.printheader();

                                //update GUI
                                MainActivity.this.runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        sendFrame.setText("Send frame #" + imagenb);
                                    }
                                });
                                //label.setText("Send frame #" + imagenb);
                            }
                            catch (NoSuchAlgorithmException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            } catch (InvalidAlgorithmParameterException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            } catch (InvalidKeySpecException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            }
                            catch (Throwable e) {
                                e.printStackTrace();
                            }
                            /*
                            catch(Exception ex)
                            {
                                System.out.println("Exception caught: "+ex);
                               // System.exit(0);
                            }
                            */
                        }
                        else
                        {
                            //if we have reached the end of the video file, stop the timer
                            // mtimer1.cancel();
                            // timer.stop();
                            // RTPsocket.close();
                            // status_close = false;
                            // stop_send();

                        }
                        //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                    }
                });

            }
        }, 0, FRAME_PERIOD);
    }

    public void timerplay2() {


        //init Timer
        // timer = new Timer(FRAME_PERIOD, this);
        // timer.setInitialDelay(0);
        // timer.setCoalesce(true);

        mtimer2.schedule(new TimerTask() {
            @Override
            public void run() {
                handler2.post(new Runnable() {
                    @Override
                    public void run() {
                        //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                        //if the current image nb is less than the length of the video
                        if (imagenb < VIDEO_LENGTH)
                        {
                            //update current imagenb
                            imagenb++;

                            try {
                                //get next frame to send from the video, as well as its size
                                int image_length = video.getnextframe(buf);
                                byte[] EN_buf2 = new byte[buf.length];
                                // encrypt

                                if(EN_STATE == DHON) {
                                    EN_buf2 = rc4_encrypt(buf, str_B_shared_key);
                                }

                                //
                                //Builds an RTPpacket object containing the frame
                                RTPpacket rtp_packet = new RTPpacket(MJPEG_TYPE, imagenb, imagenb*FRAME_PERIOD, EN_buf2, image_length);
                                //get to total length of the full rtp packet to send
                                int packet_length = rtp_packet.getlength();

                                //retrieve the packet bitstream and store it in an array of bytes
                                byte[] packet_bits = new byte[packet_length];
                                rtp_packet.getpacket(packet_bits);

                                //send the packet as a DatagramPacket over the UDP socket
                                senddp = new DatagramPacket(packet_bits, packet_length, ClientIPAddr, RTP_dest_port);
                                RTPsocket.send(senddp);

                                //System.out.println("Send frame #"+imagenb);
                                //print the header bitstream
                                rtp_packet.printheader();

                                //update GUI
                                MainActivity.this.runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        sendFrame.setText("Send frame #" + imagenb);
                                    }
                                });
                                //label.setText("Send frame #" + imagenb);
                            }

                            catch (NoSuchAlgorithmException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            } catch (InvalidAlgorithmParameterException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            } catch (InvalidKeySpecException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                            }
                            catch (Throwable e) {
                                e.printStackTrace();
                            }
                        }
                        else
                        {
                            //if we have reached the end of the video file, stop the timer
                            // mtimer2.cancel();
                            // timer.stop();
                            // RTPsocket.close();
                            // status_close = false;
                            // stop_send();

                        }
                        //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                    }
                });

            }
        }, 0, FRAME_PERIOD);
    }



    //%%%%%%%%%%%%%%%%%%%%%%%%%% ADD Server part2 Start  %%%%%%%%%%%%

    //%%%%%%%%%%%%%%%%%%%%%%%%%% ADD Server part2 End %%%%%%%%%%%%%%%%%%%%%

}
