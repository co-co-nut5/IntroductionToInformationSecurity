import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.javafx.util.Utils;
import com.sun.webkit.network.Util;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class FileEncryption extends Application{
	private static final int GCM_NONCE_LENGTH = 12;	// in bytes
	private static final int GCM_TAG_LENGTH = 16; 	// in bytes
	private Button encryptionBtn = new Button("파일 암호화");
	private Button decryptionBtn = new Button("파일 복호화");
	private TextArea infoboard = new TextArea();
	private Stage mainStage  = null;
	// 암호화/복호화키는 아래 대칭키로 고정
	private byte[] key = {(byte)0xE7, (byte)0x0B, (byte)0xC1, (byte)0xA9, (byte)0x2D, (byte)0x56, (byte)0xF5, (byte)0x13,
			(byte)0x9B, (byte)0x3E, (byte)0xAB, (byte)0x90, (byte)0x9D, (byte)0x2A, (byte)0x65, (byte)0xE5}; 
	private SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
	private Cipher cipher = null;
	
	//output 배열에 대한 내용을 16진수 형식에 맞춰 출력하는 함수
	public static void printHex(String header, byte[] output) 
	{
		System.out.println(header);
		for(int i=0; i<output.length; i++){
			System.out.printf("%02x ", output[i]);
			if((i+1)%16==0&&i!=output.length-1) System.out.println();
		}
		System.out.println();
	}
	
	private void fileDecryption(){ //복호화 함수
		FileChooser fileChooser = new FileChooser();
		File inFile = fileChooser.showOpenDialog(mainStage);
		if(inFile==null) return;
		File outFile  = new File(inFile.getAbsolutePath().substring(0,inFile.getAbsolutePath().length()-4)+".tmp");
		infoboard.setText("");
		String info = inFile.getName()+":  복호화 시작...\n";
		infoboard.setText(info);
		
		try(FileInputStream reader = new FileInputStream(inFile);
			  FileOutputStream writer = new FileOutputStream(outFile)	
			){
			/* inFile -> ~~.enc
			 * outFile -> ~~.tmp
			 */
					
			//IV + 암호문 저장하는 바이트형 리스트, 크기가 항상 다르기 때문에 ArrayList 사용
			List<Byte> input = new ArrayList<Byte>();
						
			//파일 리더기 (inFile)
            FileReader filereader = new FileReader(inFile);
            
            //지정된 파일(inFile)을 읽고 해당 바이트를 input에 저장하는 과정
            int singleCh = 0;
            while((singleCh = filereader.read()) != -1){ //원본 텍스트
                input.add((byte)singleCh);
            }
            
            //파일 리더기(inFile) 종료
            filereader.close();
            
            //IV 저장하는 바이트형 배열, 지정된 난스 크기 만큼 크기 설정
            byte[] iv = new byte[GCM_NONCE_LENGTH];
            //IV를 제외한 나머지를 저장하는 바이트형 배열, input(iv+암호문)의 크기에서 지정된 난스 크기 만큼 뺀 크기 설정
            byte[] cleartext = new byte[input.size()- GCM_NONCE_LENGTH];
          
            //iv와 암호문을 분리하는 과정
            for(int i=0;i<input.size();i++) {
            	if(i<GCM_NONCE_LENGTH) iv[i] = input.get(i);
            	else cleartext[i-GCM_NONCE_LENGTH] = input.get(i);
            }
            
            //iv와 암호문을 각각 출력
            printHex(String.format("IV(%d):", iv.length), iv);
            printHex(String.format("cleartext(%d):", cleartext.length), cleartext);
            
            //iv로 GCMParameterSpec 설정
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH*8, iv);
			
            //spec과 keySpec을 이용한 복호화 과정
         	cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
         	byte[] aad = "Associated Data".getBytes();
         	cipher.updateAAD(aad);
         	byte[] cleartext2 = cipher.doFinal(cleartext);
         	
         	//복호화 시킨 평문(원래모습)을 출력         	
         	printHex(String.format("평문(%d):", cleartext2.length), cleartext2);
         	
         	//파일 작성기(outFile)
         	FileWriter fw = new FileWriter(outFile, true);

         	//byte -> string으로 변환하여 파일(outFile)에 작성하는 과정
         	String myString = new String(cleartext2, Charset.forName("UTF-8"));
         	fw.write(myString);

         	//파일 작성기(outFile) 종료
            fw.close();         	
			
		} 


		catch (AEADBadTagException e) {
			info += inFile.getName()+":  복호화 실패. 태그 불일치\n";
			infoboard.setText(info);
			return;
		}

		catch (Exception e) {
			e.printStackTrace();
		}
		info += inFile.getName()+":  복호화 완료\n";
		infoboard.setText(info);
	}
	
	private void fileEncryption(){ //암호화 함수
		FileChooser fileChooser = new FileChooser();
		File inFile = fileChooser.showOpenDialog(mainStage);
		if(inFile==null) return;
		String info = inFile.getName()+":  암호화 시작...\n";
		infoboard.setText(info);
		File outFile  = new File(inFile.getAbsolutePath()+".enc");
		
		try(FileInputStream reader = new FileInputStream(inFile);
			  FileOutputStream writer = new FileOutputStream(outFile)	
			){
			
			/* inFile -> ~~.txt
			 * outFile -> ~~.enc
			 */
			
			// 랜덤 인자를 통해 N(iv)를 생성하는 과정
			SecureRandom csprng = SecureRandom.getInstance("SHA1PRNG");
			byte[] N = new byte[GCM_NONCE_LENGTH];
			csprng.nextBytes(N);
			
			// N 블록 출력
			printHex(String.format("N(%d):", N.length),N);

			//N으로 GCMParameterSpec 설정
			GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH*8, N);
			
			//평문을 저장하는 바이트형 리스트, 크기가 항상 다르기 때문에 ArrayList 사용
			List<Byte> input = new ArrayList<Byte>();
			
			//파일 리더기 (inFile)
            FileReader filereader = new FileReader(inFile);
            
            //지정된 파일(inFile)을 읽고 해당 바이트를 input에 저장하는 과정
            int singleCh = 0;
            while((singleCh = filereader.read()) != -1){ //원본 텍스트
                input.add((byte)singleCh);
            }
            
            //파일 리더기(inFile) 종료
            filereader.close();
            
			//input으로 부터 평문을 저장하는 바이트형 배열(input2)
            //형식을 전환하는 과정, 내용은 그대로 (arrayList -> [])
            byte[] input2 = new byte[input.size()];                     
            for(int i=0;i<input.size();i++) {
            	input2[i] = input.get(i);
            }
            
         	//평문을 출력         	
            printHex(String.format("평문(%d):", input2.length), input2);

            // iv를 먼저 outFile에 저장하는 과정
         	//파일 작성기(outFile)
            FileWriter fw = new FileWriter(outFile, true);
            
         	//iv를 파일(outFile)에 작성하는 과정
            for(int i=0;i<N.length;i++) {
            	fw.write(N[i]);
            }

            //spec과 keySpec을 이용한 암호화 과정
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
         	byte[] aad = "Associated Data".getBytes();
         	cipher.updateAAD(aad);         						
         	byte[] ciphertext = cipher.doFinal(input2);

         	// 암호문 출력
         	printHex(String.format("암호문(%d):", ciphertext.length),ciphertext);
      			
         	//암호문을 파일(outFile)에 작성하는 과정
         	for(int i=0;i<ciphertext.length;i++) {
            	fw.write(ciphertext[i]);
            }
         	
         	//파일 작성기(outFile) 종료
            fw.close();

		} 
		catch (Exception e) {
			e.printStackTrace();
		}
		info += inFile.getName()+":  암호화 완료\n";
		infoboard.setText(info);
	}
	
	@Override
	public void start(Stage primaryStage) throws Exception {
		mainStage = primaryStage;
		
		// 암호알고리즘은 AES GCM모드 사용
		cipher = Cipher.getInstance("AES/GCM/NoPadding");
		
		BorderPane mainPane = new BorderPane();
		
		HBox buttonPane = new HBox();
		buttonPane.setPadding(new Insets(10));
		buttonPane.setSpacing(10);
		buttonPane.setAlignment(Pos.CENTER);
		buttonPane.getChildren().addAll(encryptionBtn, decryptionBtn);
		encryptionBtn.setOnAction(e->fileEncryption());		
		decryptionBtn.setOnAction(e->fileDecryption());
		
		StackPane centerPane = new StackPane();
		centerPane.setPadding(new Insets(10));
		centerPane.getChildren().add(infoboard);
		infoboard.setEditable(false);
		
		mainPane.setCenter(centerPane);
		mainPane.setBottom(buttonPane);
		primaryStage.setTitle("간단 파일 암호화 도구");
		primaryStage.setScene(new Scene(mainPane,400,200));
		primaryStage.show();
	}
	public static void main(String[] args){
		Application.launch(args);
	}
}
