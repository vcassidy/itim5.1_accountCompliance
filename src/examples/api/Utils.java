/******************************************************************** 
*  Licensed Materials - Property of IBM 
*   
*  (c) Copyright IBM Corp.  2007 All Rights Reserved 
*   
*  US Government Users Restricted Rights - Use, duplication or 
*  disclosure restricted by GSA ADP Schedule Contract with 
*  IBM Corp. 
********************************************************************/ 

package examples.api; 

import java.io.FileInputStream; 
import java.io.FileNotFoundException; 
import java.io.IOException; 
import java.rmi.RemoteException; 
import java.util.HashMap; 
import java.util.Hashtable; 
import java.util.Iterator; 
import java.util.Map; 
import java.util.Properties; 
import java.util.StringTokenizer; 
import java.util.Vector; 

import javax.security.auth.Subject; 
import javax.security.auth.login.LoginContext; 
import javax.security.auth.login.LoginException; 

import com.ibm.itim.apps.ApplicationException; 
import com.ibm.itim.apps.InitialPlatformContext; 
import com.ibm.itim.apps.PlatformContext; 
import com.ibm.itim.apps.jaas.callback.PlatformCallbackHandler; 
import com.ibm.itim.common.AttributeValue; 
import com.ibm.itim.util.EncryptionManager; 

public class Utils { 
        public static final String TENANT_ID = "enrole.defaulttenant.id"; 

        public static final String LDAP_SERVER_ROOT = "enrole.ldapserver.root"; 

        public static final String TRUST_STORE = "javax.net.ssl.trustStore"; 

        public static final String TRUST_STORE_PASSWORD = "javax.net.ssl.trustStorePassword"; 

        public static final String TRUST_STORE_TYPE = "javax.net.ssl.trustStoreType"; 

        public static final String SSL_CONFIG_URL = "com.ibm.SSL.ConfigURL"; 

        private static final String LOGIN_CONTEXT = "ITIM"; 

        private static final String ITIM_HOME = "itim.home"; 

        private static final String ENROLE_PROPS = "/data/enRole.properties"; 
        
        /** 
         * erglobalid=00000000000000000000 - The rest of the DN must be appended. 
         */ 
        public static final String DEFAULT_ORG_ID = "erglobalid=00000000000000000000"; 

        /** 
         * Should the Utils class print out messages about what it is doing? 
         */ 
        private boolean verbose; 

        private String[][] required; 

        private Properties props; 

        /** 
         * Create a new Utils object to help with processing. 
         * 
         * @param requiredParams 
         *            A 2D String Array where required[x][0] is the name of a 
         *            required parameter, and required[x][1] is the error message to 
         *            present if the parameter is missing. requiredParams must not 
         *            be null. 
         * @param isVerbose 
         *            Should the Utils class print out messages about what it is 
         *            doing? <code>true</code> if Utils should be verbose, 
         *            <code>false</code> otherwise. 
         */ 
        public Utils(String[][] requiredParams, boolean isVerbose) { 
                if (requiredParams == null) { 
                        throw new IllegalArgumentException( 
                                        "Required parameter requiredParams cannot be null."); 
                } 

                required = requiredParams; 
                verbose = isVerbose; 
        } 

        /** 
         * Parses the argument list from the command-line 
         */ 
        public Hashtable<String, Object> parseArgs(String[] args) { 
                Hashtable<String, Object> arguments = new Hashtable<String, Object>(); 
                String argumentList = ""; 
                for (int i = 0; i < args.length; i++) { 
                        argumentList += args[i]; 
                } 

                StringTokenizer tokenizer = new StringTokenizer(argumentList, "-"); 
                while (tokenizer.hasMoreTokens()) { 
                        String token = (String) tokenizer.nextToken(); 
                        int delim = token.indexOf("?"); 
                        String name = token.substring(0, delim); 
                        String value = token.substring(delim + 1, token.length()); 
                        if (arguments.get(name) != null) { 
                                // arg name used previous 
                                Object vals = arguments.get(name); 
                                if (vals instanceof String) { 
                                        // convert to String[] 
                                        Vector<String> values = new Vector<String>(2); 
                                        values.add((String) vals); 
                                        values.add(value); 

                                        arguments.put(name, values); 
                                } else if (vals instanceof Vector) { 
                                        // add new element to String[] 
                                        Vector<String> values = (Vector<String>) vals; 
                                        values.add(value); 
                                        arguments.put(name, vals); 
                                } 
                        } else { 
                                arguments.put(name, value); 
                        } 
                } 

                checkArguments(arguments); 
                return arguments; 
        } 

        /** 
         * Retreives data from the following System properties: 
         * <ul> 
         * <li>apps.context.factory</li> 
         * <li>apps.server.url</li> 
         * <li>apps.ejb.user</li> 
         * <li>apps.ejb.pswd</li> 
         * </ul> 
         * 
         * @return 
         * @throws RemoteException 
         * @throws ApplicationException"javax.net.ssl.trustStoreType" 
         */ 
        public PlatformContext getPlatformContext() throws RemoteException, 
                        ApplicationException { 
                String contextFactory = getProperty("apps.context.factory"); 
                String appServerUrl = getProperty("enrole.appServer.url"); 
                String ejbUser = getProperty("enrole.appServer.ejbuser.principal"); 
                String ejbPswd = getProperty("enrole.appServer.ejbuser.credentials"); 

                // If encryption is turned on we need to decrypt the password and set 
                // a few properties for SSL. 
                String encrypted = getProperty("enrole.password.appServer.encrypted"); 
                if ("true".equalsIgnoreCase(encrypted)) { 
                        ejbPswd = EncryptionManager.getInstance().decrypt(ejbPswd); 

                        String itimHome = getProperty("itim.home"); 
                        String trustStore = getProperty(EncryptionManager.PROP_ENCRYPTION_KEYSTORE); 
                        String trustPass = getProperty(EncryptionManager.PROP_ENCRYPTION_PASSWORD); 

                        if (System.getProperty(TRUST_STORE) == null) { 
                                System.setProperty(TRUST_STORE, itimHome + "/data/keystore/" 
                                                + trustStore); 
                        } 

                        if (System.getProperty(TRUST_STORE_PASSWORD) == null) { 
                                System.setProperty(TRUST_STORE_PASSWORD, trustPass); 
                        } 

                        if (System.getProperty(TRUST_STORE_TYPE) == null) { 
                                System.setProperty(TRUST_STORE_TYPE, "JCEKS"); 
                        } 

                        if (System.getProperty(SSL_CONFIG_URL) == null) { 
                                System.setProperty(SSL_CONFIG_URL, "file:" + itimHome 
                                                + "/extensions/5.1/examples/apps/bin/ssl.client.props"); 
                        } 
                } 

                // Setup environment table to create an InitialPlatformContext 
                Hashtable<String, String> env = new Hashtable<String, String>(); 
                env.put(InitialPlatformContext.CONTEXT_FACTORY, contextFactory); 
                env.put(PlatformContext.PLATFORM_URL, appServerUrl); 
                env.put(PlatformContext.PLATFORM_PRINCIPAL, ejbUser); 
                env.put(PlatformContext.PLATFORM_CREDENTIALS, ejbPswd); 

                print("Creating new PlatformContext \n"); 

                return new InitialPlatformContext(env); 
        } 

        /** 
         * Retreives data from the following System properties: 
         * <ul> 
         * <li>itim.user</li> 
         * <li>itim.pswd</li> 
         * </ul> 
         * 
         * @param platform 
         * @return 
         * @throws LoginException 
         */ 
        public Subject getSubject(PlatformContext platform) throws LoginException { 
                String itimUser = getProperty("itim.user"); 
                String itimPswd = getProperty("itim.pswd"); 

                // Create the ITIM JAAS CallbackHandler 
                PlatformCallbackHandler handler = new PlatformCallbackHandler(itimUser, 
                                itimPswd); 
                handler.setPlatformContext(platform); 

                print("Logging in \n"); 
                // Associate the CallbackHandler with a LoginContext, then try to 
                // authenticate the user with the platform 
                LoginContext lc = new LoginContext(LOGIN_CONTEXT, handler); 
                lc.login(); 

                print("Getting subject \n"); 

                // Extract the authenticated JAAS Subject from the LoginContext 
                return lc.getSubject(); 
        } 

        /** 
         * Creates an AttributeValue from the given name=value pair. 
         * 
         * @param nameValuePair 
         *            String in the format of string=value. 
         * @return An AttributeValue object that holds the data in nameValuePair 
         */ 
        public static AttributeValue createAttributeValue(String nameValuePair) { 
                String name = nameValuePair.substring(0, nameValuePair.indexOf("=")); 
                String value = nameValuePair.substring(nameValuePair.indexOf("=") + 1, 
                                nameValuePair.length()); 
                AttributeValue attrVal = new AttributeValue(name, value);                 
                return attrVal; 
        } 

        /** 
         * Creates an AttributeValueMap from the given Vector attributes. 
         * 
         * @param attributes 
         *            Vector Form Commandline argument. 
         * 
         */ 
        public static Map<String, AttributeValue> createAttributeValueMap(Vector attributes) { 
                Iterator it = attributes.iterator(); 
                Map<String, AttributeValue> map=new HashMap<String, AttributeValue>(); 
                while (it.hasNext()) { 
                        String nameValuePair=(String)it.next(); 
                        String name = nameValuePair.substring(0, nameValuePair.indexOf("=")); 
                        String value = nameValuePair.substring(nameValuePair.indexOf("=") + 1, 
                                nameValuePair.length()); 
                        
                        if(!map.containsKey(name)){ 
                                AttributeValue attrVal = new AttributeValue(name, value);                 
                                map.put(name,attrVal); 
                        }else{ 
                                map.get(name).addValue(value); 
                        }                         
                } 
                return map; 
        }         
        
        private boolean checkArguments(Hashtable<String, Object> arguments) { 
                for (int i = 0; i < required.length; i++) { 
                        if (!arguments.containsKey(required[i][0])) { 
                                throw new IllegalArgumentException(required[i][1]); 
                        } 
                } 

                return true; 
        } 

        public String getProperty(String propName) { 
                if (props == null) { 
                        props = new Properties(); 

                        String itimHome = System.getProperty(ITIM_HOME); 
                        try { 
                                props.load(new FileInputStream(itimHome + ENROLE_PROPS)); 
                        } catch (FileNotFoundException ex) { 
                                throw new RuntimeException(ex); 
                        } catch (IOException ex) { 
                                throw new RuntimeException(ex); 
                        } 
                } 

                String value = System.getProperty(propName); 

                if (value == null) { 
                        value = props.getProperty(propName); 
                } 

                return value; 
        } 

        public void print(String msg) { 
                if (verbose) { 
                        System.out.println(msg); 
                } 
        } 
} 

