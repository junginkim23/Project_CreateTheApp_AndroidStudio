//11월 30일 수정 완료 저장.
package com.example.mobileproject.Client;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyAgreement;
//add
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.util.StringTokenizer;

import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;


import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.interfaces.DHPublicKey;

import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import android.util.Base64;
//addend
import android.os.StrictMode;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;

import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.nio.channels.DatagramChannel;
import java.util.Timer;
import java.net.InetSocketAddress;


import android.os.Handler;

import android.widget.ImageView;
import android.widget.ListView;
import android.widget.ArrayAdapter;

import com.example.mobileproject.R;

import java.lang.Throwable;

public class MainActivity extends AppCompatActivity {
    //p2p chat 코드에서 따온 변수들
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
    private Thread thread_serverStart;
    private Button startButton;
    private EditText inputMessage;
    private InetAddress PeerIP2;
    private InetAddress PeerIP1;
    private boolean Callee = false;
    private TextView receive_message;
    private int SEND_PORT = 7777;
    private int RECV_PORT = 8888;
    private int SRCV_PORT=9999;
    private String MessageInput;
    private byte[] MessageInputByte;
    private byte[] Messagelength;
    private ArrayAdapter<String> mConversationArrayAdapter;
    private ListView   mConversationView;
    private DatagramSocket send_socket;
    //private BufferedWriter out;
    //private BufferedReader in1;
    //private Socket socket;
    private Socket socket1;
    //private BufferedReader in;
    TextView OwnIP;
    //private ServerSocket listner;
    private ServerSocket listner1;
    private InetAddress Address;
    private InetAddress Address1;
//여기까지
    private InputStream is;
    private DataInputStream dis;
    private Button button_setup,button_dh, button_rsa, button_play,button_pause,button_teardown,button_play2;
    private EditText editText_ServerIP,editKeysize, editText_ServerPort,editText_videofilename;
    private ImageView image;
    private Timer mtimer1,mtimer2;
    private Handler handler1, handler2;

    //RTP variables:
    //----------------

    private  DatagramPacket rcvdp,senddp; //UDP packet received from the server
    DatagramSocket RTPsocket,RTPsocket_time; //socket to be used to send and receive UDP packets
    final static int RTP_RCV_PORT = 25000; //port where the client will receive the RTP packets
    private DatagramChannel channel;
    int messagenb=0;
    Timer timer; //timer used to receive data from the UDP socket
    private byte[] buf; //buffer used to store data received from the server
    static int Message_LENGTH = 500;
    //RTSP variables
    //----------------
    //rtsp states
    private int EN_STATE;
    private int CLEAR = 0;
    private int DHON = 1;
    private int RSAON = 2;
    private int INIT = 0;
    private int READY = 1;
    private int DHREADY = 8;
    private int CHATTING = 2;
    private int STOP = 3;
    private int state; //RTSP state == INIT or READY or PLAYING
    private Socket RTSPsocket; //socket used to send/receive RTSP messages
    private ServerSocket ss;
    private Socket s;

    private Socket socket;


    //input and output stream filters
    private BufferedReader RTSPBufferedReader,RTSPBufferedReaderP, RTSPBufferedReaderdh2,RTSPBufferedReaderrsa ;
    private BufferedWriter RTSPBufferedWriter,RTSPBufferedWriterS,RTSPBufferedWriterdh, RTSPBufferedWriterrsa;
    private BufferedWriter RTSPBufferedWriterdhp;
    private String VideoFileName; //video file to request to the server
    //Sequence number of RTSP messages within the session
    final static int inputMessage_length=5;
    final static int SETUP = 3;
    final static int PLAY = 4;
    final static int PAUSE = 5;
    final static int TEARDOWN = 6;
    final static int DHSETUP = 8;
    final static int RSASETUP = 9;
    // private String CRLF = "\r\n";

    private  String ServerHost;
    private int RTSP_server_port,reply_code;
    private Thread  timerplayThread;
    private int RTSPid = 999; //ID of the RTSP session (given by the RTSP Server)
    private String s_RTSPid; //ID of the RTSP session (given by the RTSP Server)
    private String keysize;
    private int i_keysize;


    private String CRLF = "\r\n";
    private String recv_BPubKey;
    private String RxLine;
    private ServerSocket listenSocket;
    private   AlgorithmParameterGenerator paramGen;
    private String dh_shared_secret;
    private String recovered_rsakey;
    private PrivateKey Client_RSAPrivateKey;
    private OutputStream os;
    private DataOutputStream dos;
    //Video constants:
    //------------------
    private int MJPEG_TYPE = 26; //RTP payload type for MJPEG video
    private InetAddress peerIP;
    private boolean status_connect;
    private  boolean status_mtimer2 =false,status_mtimer = true,status_mtimer_cancel=true,status_mtimer2_cancel=false,status_close = false;
    InetAddress ClientIPAddr;
    int RTP_dest_port = 0;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        setContentView(R.layout.activity_main);
        //image = (ImageView) findViewById(R.id.imageView);
        editText_ServerIP = (EditText) findViewById(R.id.editText_ServerIP);
        editKeysize = (EditText) findViewById(R.id.editKeysize);
        //editText_ServerPort = (EditText) findViewById(R.id.editText_ServerPort);
        //editText_videofilename = (EditText) findViewById(R.id.editText_videofilename);
        //p2p chat lab 5에서 따온 코드 시작
        OwnIP = (TextView) findViewById(R.id.OwnIP);
        OwnIP.setText(getIpAddress());
        //editPeerIP = (EditText)findViewById(R.id.editPeerIP);
        inputMessage = (EditText) findViewById (R.id.input_message);
        receive_message = (TextView) findViewById (R.id.receive_message);
        mConversationArrayAdapter = new ArrayAdapter<String>(this, R.layout.message);
        mConversationView = (ListView) findViewById(R.id.listView1);
        mConversationView.setAdapter(mConversationArrayAdapter);

        Log.d("VR","On create Start");
        button_setup = (Button) findViewById(R.id.button_setup);
        button_dh = (Button) findViewById(R.id.button_dh);

        button_play = (Button) findViewById(R.id.button_play);
        //        //button_pause = (Button) findViewById(R.id.button_pause);
        //button_teardown = (Button) findViewById(R.id.button_teardown);
        //button_play2=(Button) findViewById(R.id.button_play2);

        button_setup.setOnClickListener(setupListener);
        button_dh.setOnClickListener(dhListener);

        //startButton.setOnClickListener(startP2PSend); -> button_play.setOnClickListener(startP2PSend); 이렇게 바꿔야 될 때 바꾸기

        //button_pause.setOnClickListener(pauseListener);
        //button_teardown.setOnClickListener(teardownListener);

        // RTSP_server_port = Integer.parseInt(editText_ServerPort.getText().toString());
        // ServerHost = editText_ServerIP.getText().toString();
        // VideoFileName = editText_videofilename.getText().toString();

        RTSP_server_port = 18888;
        // ServerHost = "192.168.0.104";
        //VideoFileName = "movie.Mjpeg";

        //p2p chat button이 클릭되면,
        button_play.setOnClickListener(startP2PSend);
        //button_play2.setOnClickListener(startP2PSRECEIVE);
        // Thread SocketConnect = new Thread(new SocketConnectThread());
        // SocketConnect.start();
        //p2pchat에서 따온 코드
        //메세지를 받게 해주는 oncreate 내에 코드
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
        //여기까지
        // runSocketConnect();

        mtimer1 = new Timer(true);
        handler1 = new Handler();
        handler2 = new Handler();
        //mtimer = new Timer(true);
        // handler = new Handler();
        // timerplay();
        // timer = new Timer(20, new timerListener());
        // timer.setInitialDelay(0);
        //timer.setCoalesce(true);
        buf = new byte[15000];

    }
    //p2p chat

    private final OnClickListener startP2PSend = new OnClickListener() {
        //Log.d("VR", "Click OK");
        @Override
        public void onClick(View arg0) {

            runplay();

        }
    };

    /*private final OnClickListener startP2PRECEIVE = new OnClickListener() {
        //Log.d("VR", "Click OK");
        @Override
        public void onClick(View arg0) {
            runplay();
        }
    };*/


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

        }
    }
    private int parse_RTSP_request()
    {
        int request_type = -1;
        try{


            //
            Log.d("VR", "waiting for RTSPBufferedReader.readLine() ");
            //parse request line and extract the request_type:
            // RTSPBufferedReader.reset();

            String RequestLine = RTSPBufferedReader.readLine();
            System.out.println(RequestLine);
            StringTokenizer tokens = new StringTokenizer(RequestLine);
            String request_type_string = tokens.nextToken();



            Log.d("VR", "RequestLine  " + RequestLine);




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
    public void startP2PSending() {

        Thread startP2PSendingThread = new Thread (new Runnable() {
            //BufferedWriter out= null;
            //ServerSocket ss=null;
            //Socket s=null;
            //OutputStream os=null;
            //DataOutputStream dos=null;

            @Override
            public void run() {



                try {

                    MessageInput = inputMessage.getText().toString();

                    MessageInputByte = new byte[1024];
                    //ss=new ServerSocket(SRCV_PORT);
                    //s=ss.accept();
                    //os=s.getOutputStream();
                    //dos = new DataOutputStream(os);
                    //dos.writeInt(MessageInput.length());
                    if(Callee == true){
                        PeerIP1 = PeerIP2;


                                            }
                    else
                    {
                        PeerIP1 =  InetAddress.getByName(editText_ServerIP.getText().toString());
                        //Address=InetAddress.getByName(editText_ServerIP.getText().toString());

                    }
                    //메세지 길이 보내기
                    s= new Socket(PeerIP1,SRCV_PORT);//socket 생성
                    os=s.getOutputStream();
                    dos = new DataOutputStream(os);
                    dos.writeInt(MessageInput.length());
                    Log.d("VR", "MessageLEngth Send");// MessageInput을 static으로 선언. srcv_port를 static으로 선언
                    s.close();//socket을 사용하였다면, 마지막에 닫아줘야 한다.
                    //RC4 암호화
                    if(EN_STATE == DHON) {
                        MessageInputByte= rc4_encrypt(MessageInput.getBytes(), dh_shared_secret);
                        //rc4_encrypt()메소드를 이용하여 전송하고자 하는 text를 암호화. 반환은 Byte형이다.
                    }
                    final InetAddress peerIP = InetAddress.getByName(editText_ServerIP.getText().toString());
                    DatagramPacket send_packet = new DatagramPacket(MessageInputByte, MessageInputByte.length,PeerIP1,RECV_PORT);
                    //DatagramPacket 생성자를 이용해서 암호화된 text, text의 길이, 보내고자 하는 peer의 Ip 주소, 그리고 server 쪽의 port number를 매개변수로 가진다.
                    send_socket.send(send_packet);// 소켓을 통해 packet 전송
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
                }
                catch (SocketException e) {
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
    private class StartReceiveThread extends Thread {

        DatagramSocket recv_socket,RTSP_recv_socket;
        byte[] receiveData =new byte[1024];
        byte[] receiveData1=new byte[1024];
        byte[] getTheMessageLength = new byte[1024];
        int i,j;
        String inputMessage_String;
        String receive_data="";
        byte[] ByteToInput=new byte[1024];
        byte[] TrashTo=new byte[1024];
        byte[] receiveDataByte = new byte[1024];//위에 선언된 receiveData와 헷갈리지 않게 하기 위해서 ,새로운 byte형 변수 선언

        //BufferedReader in=null;
        public void run() {


            try {
                //listner = new ServerSocket(SEND_PORT);
                //socket=listner.accept();
                //in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                //inputMessage_String=in.readLine();


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
                    recv_socket.receive(recv_packet);//packet을 server쪽의 소켓을 통해 수신한다.
                    Log.d("VR", "Packet Received2");
                    if (EN_STATE == DHON) {//받은 packet안에 data를 rc4_decrypt 메소드를 이용해서 복호화.
                        receiveDataByte = rc4_decrypt(recv_packet.getData(), dh_shared_secret);
                    }
                    InetAddress sourceHost = recv_packet.getAddress();
                    PeerIP2 = sourceHost;
                    for(i=0,j=0;i<a;i++,j++){
                            ByteToInput[j] = receiveDataByte[i];
                    }
                    receive_data = new String(ByteToInput);//수신한 Data의 Byte형을 string형으로 바꿔준다.
                    Callee = true;
                    final String sourceIP = sourceHost.getHostName();
                    MainActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            mConversationArrayAdapter.add("Message from " + sourceIP + " : " + receive_data);
                        }
                    });

                }

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (Throwable e) {
                e.printStackTrace();
            }

        }
    }

    //p2p chat getIpAdress method
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
// 여기 까지


    /*private f
    inal OnClickListener pauseListener = new OnClickListener() {
        @Override
        public void onClick(View arg0) {
            runpause();
        }
    };*/
    private final OnClickListener setupListener = new OnClickListener() {
        @Override
        public void onClick(View arg0) {

            status_connect = false;
            start_TCP_connection();
            while (status_connect == false) {
                // Log.d("mediaRecorder", "enter while loop: status_sending is TRUE");
                try {
                    Thread.sleep(50);
                    // Log.d("VS", "Thread WAKES UP");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                if(status_connect == true){
                    break;
                }
            }
            runsetup();

            //runsetup();

        }
    };
    private final OnClickListener dhListener = new OnClickListener() {
        @Override
        public void onClick(View arg0) {

            //status_connect = false;
            send_RTSP_dhrequest("DHSETUP");

        }
    };




    /*private final OnClickListener teardownListener = new OnClickListener() {
        @Override
        public void onClick(View arg0) {
            runteardown();
        }
    };*/




    private void start_TCP_connection(){
        status_connect = false;

        Runnable run_start_TCP_connection = new Runnable() {
            @Override
            public void run() {

                try {
                    InetAddress ServerIPAddr = InetAddress.getByName(editText_ServerIP.getText().toString());
                    keysize = editKeysize.getText().toString();
                    i_keysize =  Integer.parseInt(keysize);
                    RTSPsocket = new Socket(ServerIPAddr, RTSP_server_port);

                    RTSPBufferedReader = new BufferedReader(new InputStreamReader(RTSPsocket.getInputStream()));
                    RTSPBufferedWriter = new BufferedWriter(new OutputStreamWriter(RTSPsocket.getOutputStream()));

                    //init RTSP state:
                    state = INIT;
                    status_connect = true;

                } catch (IOException e) {

                }


            }
        };
        Thread thread_start_TCP_connection= new Thread(run_start_TCP_connection,"run_start_TCP_connection");
        thread_start_TCP_connection.start();

    }



    //------------------------------------
    //Send RTSP Request
    //------------------------------------
//DH KEY EXCHANGE 하는 메소드<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    private void send_RTSP_dhrequest(final String request_type) {

        // send_RTSP_dhrequest("DHSETUP") called;

        Runnable T_send_RTSP_dhrequest = new Runnable() {
            @Override
            public void run() {

                try {
                    //Use the RTSPBufferedWriter to write to the RTSP socket


                    // dos = new DataOutputStream(new BufferedOutputStream(RTSPsocket.getOutputStream()));
                    // dis = new DataInputStream(new BufferedInputStream(RTSPsocket.getInputStream()));
                    //  Log.d("VS", "Client Socket Created");
                    // MessageInput = editKeysize.getText().toString();
                    //final InetAddress PeerIP = InetAddress.getByName(editText_ServerIP.getText().toString());
                    //%%%%%%%%%%%%%%%%%%%%%
                    paramGen = AlgorithmParameterGenerator.getInstance("DH");
                    // final String keysize = editKeysize.getText().toString();
                    // final int i_keysize =  Integer.parseInt(keysize);
                    paramGen.init(i_keysize);// number of bits
                    AlgorithmParameters params = paramGen.generateParameters();
                    DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);

                    BigInteger prime = dhSpec.getP();
                    final String S_prime = prime.toString();
                    BigInteger alpha = dhSpec.getG();
                    final String S_alpha = alpha.toString();


                    //A
                    KeyPairGenerator akpg = KeyPairGenerator.getInstance("DH");
                    DHParameterSpec param = new DHParameterSpec(prime, alpha);

                    akpg.initialize(param);
                    KeyPair A_kp = akpg.generateKeyPair(); //public key (Ya) and private key (Xa) of A
                    final BigInteger A_PubKey = ((javax.crypto.interfaces.DHPublicKey) A_kp.getPublic()).getY();
                    final String S_A_PubKey = Base64.encodeToString(A_kp.getPublic().getEncoded(), Base64.NO_WRAP);


                    RTSPBufferedWriterdh = new BufferedWriter(new OutputStreamWriter(RTSPsocket.getOutputStream()));
                    RTSPBufferedWriterdh.write("DHSETUP "  + keysize + " " + S_prime + '\n');
                    // RTSPBufferedWriterdh.flush();
                    //write the CSeq line:
                    RTSPBufferedWriterdh.write("S-alphadh " + S_alpha  + '\n');
                    //RTSPBufferedWriterdh.newLine();
                    // RTSPBufferedWriterdh.flush();
                    //check if request_type is equal to "SETUP" and in this case write the Transport: line advertising to the server the port used to receive the RTP packets RTP_RCV_PORT
                    // RTSPBufferedWriterdh.write(S_alpha + " " + S_A_PubKey + CRLF);

                    s_RTSPid= String.valueOf(RTSPid);
                    RTSPBufferedWriterdh.write("S_pubkeydh "  + S_A_PubKey  + '\n' );
                    //RTSPBufferedWriterdh.write("Sessiondh: " + s_RTSPid );
                    // RTSPBufferedWriterdh.newLine();
                    RTSPBufferedWriterdh.flush();
                    Log.d("VS", " 11111 Sessiondh: write pass " );

                    /*RTSPBufferedWriter.write(request_type + " " + keysize + " " + S_prime + CRLF);
                    RTSPBufferedWriter.flush();
                    //write the CSeq line:
                    RTSPBufferedWriter.write(S_alpha + " " + S_A_PubKey + CRLF);
                    RTSPBufferedWriter.flush();
                    //check if request_type is equal to "SETUP" and in this case write the Transport: line advertising to the server the port used to receive the RTP packets RTP_RCV_PORT

                    RTSPBufferedWriter.write("Sessiondh: " + RTSPid + CRLF);

                    RTSPBufferedWriter.flush();
*/

                    //final String M_Line = dis.readUTF();
                    //client_socket.send(send_packet);
                    Log.d("VR", "DHRequest Send");

                    //Thread.sleep(200);
                    //parse status line and extract the reply_code:
                    RTSPBufferedReaderdh2 = new BufferedReader(new InputStreamReader(RTSPsocket.getInputStream()));
                    String StatusLine = RTSPBufferedReaderdh2.readLine();
                    String paraLine = RTSPBufferedReaderdh2.readLine();
                    String SessionLine = RTSPBufferedReaderdh2.readLine();//11111
                    Log.d("VS", " 11111 SessionLine = " +SessionLine);
                    Log.v("VS", StatusLine);
                    //System.out.println("RTSP Client - Received from Server:");
                    System.out.println(StatusLine);

                    StringTokenizer tokens = new StringTokenizer(StatusLine);
                    tokens.nextToken(); //skip over the RTSP version
                    reply_code = Integer.parseInt(tokens.nextToken());
                    //in_reply_code = reply_code;
                    Log.v("VS", String.valueOf(reply_code));

                    //if reply code is OK get and print the 2 other lines
                    if (reply_code == 200) {
                        // String SeqNumLine = RTSPBufferedReaderP.readLine();
                        Log.v("VS", paraLine);
                        System.out.println(paraLine);
                        StringTokenizer tokenizedLine = new StringTokenizer(paraLine);
                        final String Type2 = tokenizedLine.nextToken();

                        recv_BPubKey = tokenizedLine.nextToken();
                        Log.v("VS"," recv_BPubKey = tokenizedLine.nextToken()");
                        // String SessionLine = RTSPBufferedReaderP.readLine();
                        Log.v("VS", SessionLine);
                        System.out.println(SessionLine);

                        //if state == INIT gets the Session Id from the SessionLine
                        //tokens = new StringTokenizer(SessionLine);
                        //tokens.nextToken(); //skip over the Session:
                        //RTSPid = Integer.parseInt(tokens.nextToken());
                        Log.d("VS", "RTSPid = " +String.valueOf( RTSPid));
                    }
                    //

                    byte[] publicBytes = Base64.decode(recv_BPubKey.getBytes(), Base64.NO_WRAP);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("DH");
                    PublicKey B_publicKey = keyFactory.generatePublic(keySpec);

                    final BigInteger A_SharedSecret = getSharedKey(B_publicKey, A_kp.getPrivate());
                    dh_shared_secret = A_SharedSecret.toString();
                    EN_STATE = DHON;
                    Log.d("VS", "A's shared DH key = " + A_SharedSecret.toString());
                        /*

                        MainActivity.this.runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                sharedkey.setText("A's shared DH key = " + A_SharedSecret.toString());
                            }
                        });*/


                } catch (SocketException e) {
                    Log.e("VR", "Sender SocketException");
                } catch (IOException e) {
// TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (InvalidParameterSpecException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (InvalidAlgorithmParameterException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (InvalidKeySpecException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }


            }
        };



        Thread run_send_RTSP_dhrequest = new Thread(T_send_RTSP_dhrequest, "Run_send_RTSP_dhrequest");
        run_send_RTSP_dhrequest.start();


    }
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    //DH KEY EXC에서 사용한 공개키 생성 메소드<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    private static PublicKey generateRSAPublicKey(BigInteger n, BigInteger e) throws NoSuchAlgorithmException, InvalidKeySpecException {


        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PublicKey RSAPublicKey  = fact.generatePublic(rsaPublicKeySpec);
        // TODO Auto-generated method stub
        return RSAPublicKey ;
    }

    private static PrivateKey generateRSAPrivateKey(BigInteger n, BigInteger d) throws NoSuchAlgorithmException, InvalidKeySpecException {

        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(n, d);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey RSAPrivateKey = fact.generatePrivate(rsaPrivateKeySpec);
        // TODO Auto-generated method stub
        return RSAPrivateKey;
        // TODO Auto-generated method stub
    }
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>




    public static byte[] encrypt(byte[] text, PublicKey key) {
        byte[] cipherText = new byte[text.length];
        Cipher cipher;
        try {
            // get an RSA cipher object and print the provider
            cipher = Cipher.getInstance("RSA");
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // cipherText = cipher.doFinal(text.getBytes());
            cipherText = cipher.doFinal(text);
            //string.getBytes(StandardCharsets.UTF_8)
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }
    public static byte[] charArray2ByteArray(char[] chars){
        int length = chars.length;
        byte[] result = new byte[length*2];
        int i = 0;
        for(int j = 0 ;j<chars.length;j++){
            result[i++] = (byte)( (chars[j] & 0xFF00) >> 8 );
            result[i++] = (byte)((chars[j] & 0x00FF)) ;
        }
        return result;
    }

    public static char[] byte2CharArray(byte[] data){

        char[] chars = new char[data.length/2];
        for(int i = 0 ;i<chars.length;i++){
            chars[i] = (char)( ((data[i*2] & 0xFF) << 8 ) + (data[i*2+1] & 0xFF)) ;
        }
        return chars;
    }
    /**
     * Converts a given datagram packet's contents to a String.
     */
    static String stringFromPacket(DatagramPacket packet) {
        return new String(packet.getData(), 0, packet.getLength());
    }

    /**
     * Converts a given String into a datagram packet.
     */
    static void stringToPacket(String s, DatagramPacket packet) {
        byte[] bytes = s.getBytes();
        System.arraycopy(bytes, 0, packet.getData(), 0, bytes.length);
        packet.setLength(bytes.length);
    }


    private static BigInteger getSharedKey(PublicKey pubKey,PrivateKey privKey)
            throws NoSuchAlgorithmException, InvalidKeyException  {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(privKey);
        ka.doPhase(pubKey, true);
        byte[] b = ka.generateSecret();
        BigInteger secretKey  = new BigInteger(b);
        return secretKey ;
    }

    public void runsetup() {

        if (state == INIT)
        {
            //Init non-blocking RTPsocket that will be used to receive data
            try{
                //construct a new DatagramSocket to receive RTP packets from the server, on port RTP_RCV_PORT
                // RTPsocket = new DatagramSocket(RTP_RCV_PORT);
                //RTPsocket.setReuseAddress(true);

                channel = DatagramChannel.open();
                Log.v("VS", "channel OPEN");
                channel.socket().bind(new InetSocketAddress(RTSPsocket.getLocalAddress(), RTP_RCV_PORT));
                Log.v("VS", "LOCAL IP:"+ RTSPsocket.getLocalAddress());
                Log.v("VS", "channel BINDED");
                channel.configureBlocking(false);
                EN_STATE = CLEAR;

                //set TimeOut value of the socket to 5msec.
                //RTPsocket.setSoTimeout(5);
            }
            catch (SocketException se)
            {
                System.out.println("Socket exception: "+se);
                System.exit(0);
            }catch (IOException e){

            }

            //init RTSP sequence number
            RTSPSeqNb = 1;

            //Send SETUP message to the server
            send_RTSP_request("SETUP");
            Log.v("VS", "SETUP SEND");

            //Wait for the response
            if (parse_server_response() != 200) {
                Log.v("VS", "Reply code return value = " + String.valueOf(reply_code));
                System.out.println("Invalid Server Response");
            }
            else
            {
                //change RTSP state and print new state
                state = READY;
                System.out.println("New RTSP state: READY");
            }
        }//else if state != INIT then do nothing
    }

    public void runplay() {

        Runnable startrunplay = new Runnable() {
            @Override
            public void run() {
                if (state == READY || state ==PLAY || state==CHATTING)
                {
                    //increase RTSP sequence number
                    RTSPSeqNb++;

                    //Send PLAY message to the server
                    send_RTSP_request_play("PLAY"); //일단 대기.  이거 대신 startp2psending 메소드 쓰고 싶다.
                    startP2PSending();


                    //Wait for the response
                    if (parse_server_response() != 200) //그리고 이 부분은 응답이 오면, 그리고 서버에 뜨는 rtsp state.이 chatting으로 뜨게 하는 것.
                        //Log.v("VS", String.valueOf(reply_code));
                        System.out.println("Invalid Server Response in PLAY");
                    else
                    {
                        //change RTSP state and print out new state
                        state = CHATTING;
                        System.out.println("New RTSP state: CHATTING");

                    }
                }//else if state != READY then do nothing
            }
        };
        Thread threadRunPlay = new Thread(startrunplay,"thread runplay");
        threadRunPlay.start();

    }

    //rc4_encrypt<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
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
    //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//rc4_decrypt<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    public   byte[] rc4_decrypt(byte[] ciphertext, String B_shared_key)throws  NoSuchAlgorithmException, InvalidKeyException, Throwable {
        byte[] clearText;
        byte[] cipherText = new byte[ciphertext.length];

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
            int counter = 0;
            while (counter < ciphertext.length) {
                cipherText[counter] = (byte)ciphertext[counter];
                counter++;
            }
            Cipher rc4 = Cipher.getInstance("RC4");
            SecretKeySpec rc4Key = new SecretKeySpec(B_shared_key.getBytes(), "RC4");
            rc4.init(Cipher.DECRYPT_MODE, rc4Key);
            clearText = rc4.update(cipherText);
            //System.out.println(new String(clearText, "ASCII"));
            return clearText;
        } catch (Exception e) { return null; }


    }
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    //------------------------------------
    //Parse Server Response
    //------------------------------------
    private int parse_server_response()
    {
        reply_code = 0;
        Runnable run_parse_server_response = new Runnable() {
            @Override
            public void run() {
                try{
                    //int in_reply_code = 0;
                    //parse status line and extract the reply_code:
                    RTSPBufferedReaderP = new BufferedReader(new InputStreamReader(RTSPsocket.getInputStream()));
                    String StatusLine = RTSPBufferedReaderP.readLine();
                    String SeqNumLine = RTSPBufferedReaderP.readLine();
                    String SessionLine = RTSPBufferedReaderP.readLine();
                    // Log.v("VS", StatusLine);
                    // Log.v("VS", SeqNumLine);//Log.v("VS", SessionLine);
                    //System.out.println("RTSP Client - Received from Server:");
                    // System.out.println(StatusLine);

                    StringTokenizer tokens = new StringTokenizer(StatusLine);
                    tokens.nextToken(); //skip over the RTSP version
                    reply_code = Integer.parseInt(tokens.nextToken());
                    //in_reply_code = reply_code;
                    //Log.v("VS", String.valueOf(reply_code));

                    //if reply code is OK get and print the 2 other lines
                    if (reply_code == 200)
                    {
                        // String SeqNumLine = RTSPBufferedReaderP.readLine();
                        //Log.v("VS", SeqNumLine +String.valueOf(reply_code) );
                        //System.out.println(SeqNumLine);

                        // String SessionLine = RTSPBufferedReaderP.readLine();
                        //Log.v("VS", SessionLine);
                        //System.out.println(SessionLine);

                        //if state == INIT gets the Session Id from the SessionLine
                        tokens = new StringTokenizer(SessionLine);
                        tokens.nextToken(); //skip over the Session:
                        RTSPid = Integer.parseInt(tokens.nextToken());
                    }
                    else {
                        System.out.println("reply not 200 ");
                        System.exit(0);

                    }
                }
                catch(Exception ex) {
                    Log.v("VS", "SERVER RESPONSE NOT RECEIVED");
                    System.out.println("Exception caught : " + ex);

                    // System.exit(0);
                }


            }
        };

        Thread threadRun = new Thread(run_parse_server_response,"thread run");
        threadRun.start();
        try {
            Thread.sleep(900);
        }catch (InterruptedException e){

        }
        return(reply_code);

    }

    // send rtsp request start
    //------------------------------------
    //Send RTSP Request
    //------------------------------------
//사실 이것도 필요 없다고 생각함.
    private void send_RTSP_request(final String request_type)
    {
        Runnable Run_send_RTSP_request = new Runnable() {
            @Override
            public void run() {

                try{
                    //Use the RTSPBufferedWriter to write to the RTSP socket

                    //write the request line:
                    s_RTSPid = String.valueOf(RTSPid);
                    s_RTSPSeqNb = String.valueOf(RTSPSeqNb);
                    RTSPBufferedWriterS = new BufferedWriter(new OutputStreamWriter(RTSPsocket.getOutputStream()));
                    RTSPBufferedWriterS.write(request_type + " " + VideoFileName + " RTSP/1.0" + '\n');

                    //write the CSeq line:
                    RTSPBufferedWriterS.write("CSeq: " + s_RTSPSeqNb + '\n');

                    // Thread.sleep(500);
                    //check if request_type is equal to "SETUP" and in this case write the Transport: line advertising to the server the port used to receive the RTP packets RTP_RCV_PORT
                    if ((new String(request_type)).compareTo("SETUP") == 0)
                        RTSPBufferedWriterS.write("Transport: RTP/UDP; client_port= "+RTP_RCV_PORT+'\n');
                    if ((new String(request_type)).compareTo("PLAY") == 0)
                    {RTSPBufferedWriterS.write("Session123: " + s_RTSPid + '\n');

                    }

                    RTSPBufferedWriterS.flush();
                    //RTSPBufferedWriterS.close();


                }
                catch(Exception ex)
                {
                    System.out.println("Exception caught : "+ex);
                    System.exit(0);
                }

            }
        };
        Thread run_send_RTSP_request = new Thread(Run_send_RTSP_request,"Run_send_RTSP_request");
        run_send_RTSP_request.start();

    }

    private void send_RTSP_request_play(final String request_type)
    {


        try{
            //Use the RTSPBufferedWriter to write to the RTSP socket

            //write the request line:
            s_RTSPid = String.valueOf(RTSPid);
            s_RTSPSeqNb = String.valueOf(RTSPSeqNb);
            RTSPBufferedWriterdhp = new BufferedWriter(new OutputStreamWriter(RTSPsocket.getOutputStream()));
            RTSPBufferedWriterdhp.write(request_type + " " + VideoFileName + " RTSP/1.0" + '\n');
            Log.d("VR", request_type + " " + VideoFileName + " RTSP/1.0" + '\n'); //write the CSeq line:
            RTSPBufferedWriterdhp.write("CSeq: " + s_RTSPSeqNb + '\n');
            Log.d("VR", "CSeq: " + s_RTSPSeqNb + '\n');// Thread.sleep(500);
            //check if request_type is equal to "SETUP" and in this case write the Transport: line advertising to the server the port used to receive the RTP packets RTP_RCV_PORT
            RTSPBufferedWriterdhp.write("Session123: " + s_RTSPid + '\n');
            Log.d("VR", "Session123: " + s_RTSPid + '\n');
            //   RTSPBufferedWriterdh.newLine();

            RTSPBufferedWriterdhp.flush();
            //RTSPBufferedWriterS.close();


        }
        catch(Exception ex)
        {
            System.out.println("Exception caught : "+ex);
            System.exit(0);
        }

    }

}
