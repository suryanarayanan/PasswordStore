

package passwordstore;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.Scanner;

/**
 *
 * @author Surya
 */
class InputEraser extends Thread {
    PrintStream out;
    boolean finish = false;

    public InputEraser(PrintStream out){
        this.out = out;
    }

    @Override /* Thread run method */
    public void run(){
        while (!finish){
            /* Replace last character with blank */
            out.print("\b ");
            try{
                /* Sleep short time */
                sleep(1);
            }
            catch (InterruptedException interrupt){
                finish = true;
            }
        }
    }

    /* Read one line from system.in */
    public static String readLine(){
        InputEraser eraser = new InputEraser(System.out);
        eraser.start();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String password = "";
        try{
            password = in.readLine();
        }
        catch (IOException ioe){
            System.out.println("Error in Input !");
            ioe.printStackTrace();
            password = "";
            return password;
        }
        /* stop InputEraser thread */
        eraser.interrupt();
        return password;
    }
}

public class PasswordStore {

   /* Master key used to encrypt/decrypt the username password */
   private String masterkey;
   /* website address */
   private String sitename;
   /* user name for the website */
   private String username;
   /* password for the website */
   private String password;
   /* Storage File*/
   
   public void help(){
       System.out.println("To add a new entry, use -add");
       System.out.println("To update an already existing entry, use -update");
       System.out.println("To retrieve passwords, use -get");
   }
   int getCount(int a){
       int cnt=0;
       while(a>0){
           cnt++;
           a/=10;
       }
       return cnt;
   }

   public void encryptAndStore(String sitename,String username,String password,String masterkey,String action){
       int count = username.length();
       int countCount = getCount(count);
       String userAndPass = username + password + count + countCount;
       PasswordBasedEncryption pencrypt = new PasswordBasedEncryption();
       String encryptedUserAndPass = pencrypt.encrypt(userAndPass, masterkey);
       new FileManager().storeData(sitename,encryptedUserAndPass,masterkey,action);
   }
   public void addEntry(){
       Scanner scan = new Scanner(System.in);
       String hasMoreEntries;
       String reEnter;
       do{
            System.out.print("\bEnter the MasterKey       : ");
            masterkey = InputEraser.readLine();
            System.out.print("\bConfirm the MasterKey     : ");
            reEnter = InputEraser.readLine();
       }while(!masterkey.equals(reEnter));

       do{
            System.out.print("\bEnter the Website         : ");
            sitename = scan.nextLine();
            System.out.print("Enter the Username        : ");
            username = scan.nextLine();
            System.out.print("Enter the Password        : ");
            password = InputEraser.readLine();
            encryptAndStore(sitename,username,password,masterkey,"add");
            do{
                System.out.print("\bHave more entries         : yes | no ? ");
                hasMoreEntries = scan.nextLine();
            }while(!(hasMoreEntries.equalsIgnoreCase("yes")) && !(hasMoreEntries.equalsIgnoreCase("no")));
       }while(hasMoreEntries.toLowerCase().equalsIgnoreCase("yes"));
   }

   public void updateEntry(){
       Scanner scan = new Scanner(System.in);
       String hasMoreEntries;
       String reEnter;
       do{
            System.out.print("\bEnter the MasterKey       : ");
            masterkey = InputEraser.readLine();
            System.out.print("\bConfirm the MasterKey     : ");
            reEnter = InputEraser.readLine();
       }while(!masterkey.equals(reEnter));
       do{
            System.out.print("\bEnter the Website         : ");
            sitename = scan.nextLine();
            System.out.print("Enter the Username        : ");
            username = scan.nextLine();
            System.out.print("Enter the Password        : ");
            password = InputEraser.readLine();
            encryptAndStore(sitename,username,password,masterkey,"update");
            do{
            System.out.print("\bUpdate more?              : yes | no ? ");
                hasMoreEntries = scan.nextLine();
            }while(!(hasMoreEntries.equalsIgnoreCase("yes")) && !(hasMoreEntries.equalsIgnoreCase("no")));
        }while(hasMoreEntries.toLowerCase().equalsIgnoreCase("yes"));
   }

   public void get(){
       Scanner scan = new Scanner(System.in);
       System.out.print("Enter the Website         : ");
       String website = scan.nextLine();
       System.out.print("Enter the MasterKey       : ");
       String passkey = InputEraser.readLine();
       new FileManager().getData(website,passkey);
   }
   
   public void list(){
	System.out.println("Stored contents : ");
	new FileManager().listData();
   }
  /* Default Constructor */
   public PasswordStore(){}
   /* Constructor to be invoked wen the program runs */
   public PasswordStore(String args[])throws Exception {
    try {
        if (args.length == 1) {
           if(args[0].equalsIgnoreCase("-add")){
                /*Adds entry to the store file*/
                addEntry();
           }
           else if(args[0].equalsIgnoreCase("-update")){
                /*Update already existing entry in the store file*/
                updateEntry();
           }
           else if(args[0].equalsIgnoreCase("-get")){
                get();
           }
		   else if(args[0].equalsIgnoreCase("-list")){
				list();
		   }
           else {
                /* invalid command */
                help();
           }
        }
        else{
           help();
        }
    } catch (Exception e) {
        /* throw it so that Agent can display a usage message */
        throw e;
    }
   }
   public static void main(String args[])throws Exception{
   //    Provider jsafeProvider = new com.rsa.jsafe.provider.JsafeJCE();
   //    Security.addProvider(jsafeProvider);
       PasswordStore pass = new PasswordStore(args);
       System.out.println("Have a good time !");
   }
}
