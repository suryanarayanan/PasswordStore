
package passwordstore;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Scanner;
import java.util.Enumeration;
/**
 *
 * @author Surya
 */

public class FileManager {
        private static final String defaultFile = "pass.stor";
        void storeData(String key,String value,String masterkey,String action){
            String answer;
            try{
                FileOutputStream fstream = new FileOutputStream(FileManager.defaultFile,true);
                Properties prop = new Properties();
                prop.load(new FileInputStream(FileManager.defaultFile));
                fstream.close();
                if(prop.getProperty(key)== null){
                    if(action.equals("add")){
                        prop.setProperty(key, value);
                    }
                    else if(action.equals("update")){
                        Scanner scan = new Scanner(System.in);
                        do{
                              System.out.print("\bThe website doesn't exist ! Do you wanna add this ? yes|no :");
                              answer = scan.nextLine();
                              if(answer.equalsIgnoreCase("yes")){
                                  prop.setProperty(key , value);
                              }
                              else if(answer.equalsIgnoreCase("no")){
                                  return;
                              }
                          }while(!answer.equalsIgnoreCase("yes") && !answer.equalsIgnoreCase("no"));
                    }
                }
               else{
                    if(action.equals("add")){
                        String existing = prop.getProperty(key);
                        try{
                            new PasswordBasedEncryption().decrypt(existing, masterkey);
                        }catch(Exception e){
                            System.out.println("\bInvalid Masterkey !");
                            return;
                        }
                        Scanner scan = new Scanner(System.in);
                        do{
                            System.out.print("\bWebsite Already Exists. Do you want to overwrite it? yes|no : ");
                            answer = scan.nextLine();
                            if(answer.equalsIgnoreCase("yes")){
                                prop.setProperty(key , value);
                            }
                            else if(answer.equalsIgnoreCase("no"))return;
                        }while(!answer.equalsIgnoreCase("yes") && !answer.equalsIgnoreCase("no"));
                    }
                    else{
                        String existing = prop.getProperty(key);
                        try{
                           new PasswordBasedEncryption().decrypt(existing, masterkey);
                        }catch(Exception e){
                           System.out.println("\bInvalid Masterkey !");
                           return;
                        }
                        prop.setProperty(key,value);
                     }
               }
               fstream = new FileOutputStream(FileManager.defaultFile);
               prop.store(fstream, "");
               fstream.close();
               System.out.println("\b1 Entry successfully Stored !");
            }catch(Exception e){
                System.out.println("\bProblem with storing data. Check pass.stor !");
            }
        }

        void getData(String website,String passkey){
           try{
               PasswordBasedEncryption pbe = new PasswordBasedEncryption();
               Properties prop = new Properties();
               prop.load(new FileInputStream(FileManager.defaultFile));
               String encUserAndPass = prop.getProperty(website);
               if(encUserAndPass == null){
                   System.out.println("\bOOps..Website not found or Invalid Masterkey !");
                   return;
               }
               String userAndPass = pbe.decrypt(encUserAndPass, passkey);
               int userAndPassLen = userAndPass.length();
               int usernameLengthCount = Integer.parseInt((userAndPass.charAt(userAndPassLen-1))+"");
               int usernameLength
                       = Integer.parseInt(userAndPass.substring(userAndPassLen-usernameLengthCount-1, userAndPassLen-1));
               System.out.print("\bRetrieving ");
               int cnt=0;
               do{
                   System.out.print(".");
                   Thread.sleep(300);
                   cnt++;
               }while(cnt!=5);
               System.out.println("");
               System.out.println("Your Username             : "+userAndPass.substring(0, usernameLength));
               System.out.println("Your Password             : "+userAndPass.substring(usernameLength,userAndPassLen-1-usernameLengthCount));
           }catch(Exception e){
               System.out.println("\bInvalid Masterkey !");
           }
        }
		
		void listData(){
			Properties prop = new Properties();
			String key, value = null;

			try {
				prop.load(new FileInputStream(FileManager.defaultFile));
				/* get an enumeration of all keys */
				Enumeration<?> keys = prop.propertyNames();
				/* loop through keys and display the key:value pairs */
				while (keys.hasMoreElements()) {
					key = keys.nextElement().toString();
					System.out.println(key);
				}
			} catch (Exception e) {
				System.out.println("Display key/values failed:" + e.getLocalizedMessage());
			}
		}
}
