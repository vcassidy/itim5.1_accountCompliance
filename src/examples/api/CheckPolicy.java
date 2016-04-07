package examples.api;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;


import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import com.ibm.itim.apps.ApplicationException;
import com.ibm.itim.apps.AuthorizationException;
import com.ibm.itim.apps.PlatformContext;
import com.ibm.itim.apps.SchemaViolationException;
import com.ibm.itim.apps.identity.PersonMO;
import com.ibm.itim.apps.provisioning.AccountMO;
import com.ibm.itim.apps.provisioning.AccountManager;
import com.ibm.itim.apps.provisioning.Compliance;
import com.ibm.itim.apps.provisioning.ServiceMO;
import com.ibm.itim.apps.search.SearchMO;
import com.ibm.itim.apps.search.SearchResultsMO;
import com.ibm.itim.common.AttributeChangeOperation;
import com.ibm.itim.common.AttributeChanges;
import com.ibm.itim.common.AttributeValue;
import com.ibm.itim.common.AttributeValues;
import com.ibm.itim.dataservices.model.CompoundDN;
import com.ibm.itim.dataservices.model.DistinguishedName;
import com.ibm.itim.dataservices.model.ObjectProfileCategory;
import com.ibm.itim.dataservices.model.domain.Account;
import com.ibm.itim.dataservices.model.domain.Person;

/**
 * Sample command-line Java class to change an account.
 */
public class CheckPolicy {
	/**
	 * Command line argument names (prefixed by "-")
	 */
	private static final String PROFILE = "profile";

	private static final String ACCOUNT_FILTER = "accountfilter";

	private static final String FILEPATH = "filepath";

	private static final String[][] utilParams = new String[][] {
			{ PROFILE, "No profile specified" },
			{ ACCOUNT_FILTER, "No accountfilter specified" },
			{ FILEPATH, "No filepath specified" } };

	private static String userName;

	private static String serviceName;

	private static Object complianceStr;

	public static void main(String[] args) {
		run(args, true);
	}

	/**
	 * Run the example.
	 * 
	 * @param args
	 *            Arguments passed in, usually from the command line. See usage
	 *            from more information.
	 * @param verbose
	 *            Should the program print out lots of information.
	 * @return true if run() completes successfully, false otherwise.
	 */
	@SuppressWarnings("deprecation")
	public static boolean run(String[] args, boolean verbose) {

		Utils utils = null;
		Hashtable<String, Object> arguments = null;
		PlatformContext platform = null;

		try {
			utils = new Utils(utilParams, verbose);
			arguments = utils.parseArgs(args);
		} catch (IllegalArgumentException ex) {
			if (verbose) {
				System.err.println(getUsage(ex.getMessage()));
			}
			return false;
		}
		String accountProfile = (String) arguments.get(PROFILE);
		String accountFilter = (String) arguments.get(ACCOUNT_FILTER);
		String filePath = (String) arguments.get(FILEPATH);

		utils.print(accountProfile+": account profile \n");
		utils.print(accountFilter + ": accountFilter \n");
		utils.print(filePath + ":  filePath \n");
		File file = new File(filePath);
		if (!file.exists()) {
			try {
				file.createNewFile();
			} catch (IOException e) {
				utils.print("Error creating file +e.toString() \n");
			}
		}

		FileWriter fw = null;
		try {
			fw = new FileWriter(file.getAbsoluteFile());
		} catch (IOException e1) {
			utils.print("Error creating filewriter:" + e1.toString());
		}

		BufferedWriter print = new BufferedWriter(fw);

		try {
			String tenantId = utils.getProperty(Utils.TENANT_ID);
			String ldapServerRoot = utils.getProperty(Utils.LDAP_SERVER_ROOT);
			platform = utils.getPlatformContext();
			Subject subject = utils.getSubject(platform);

			// platform = utils.getPlatformContext();
			// Subject subject = utils.getSubject();

			utils.print("Searching for Account \n");
			// Use the Search API to locate the Account to deprovision

			SearchMO searchMO = new SearchMO(platform, subject);
			searchMO.setCategory(ObjectProfileCategory.ACCOUNT);

			String dn = "ou=" + tenantId + "," + ldapServerRoot;
			searchMO.setContext(new CompoundDN(new DistinguishedName(dn)));
			searchMO.setProfileName(accountProfile);
			searchMO.setFilter(accountFilter);
			SearchResultsMO searchResultsMO = null;
			Collection<Account> accounts = null;
			try {
				searchResultsMO = searchMO.execute();
				accounts = searchResultsMO.getResults();
				if (accounts.size() == 0) {
					utils.print("No matching account found.");
					return false;

				}
			} finally {
				utils.print(accounts.size() + " found accounts to process \n");
				// close SearchResultsMO
				if (searchResultsMO != null) {
					try {
						searchResultsMO.close();
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
			AccountManager accMgr = new AccountManager(platform, subject);

			utils.print("userName;" + "serviceName;" + "complianceStatus;"
					+ "attrName;" + "attrChangeOperation;" + "oldValue;"
					+ "newValue" + "\n");

			try {
				print.write("userName;" + "serviceName;" + "complianceStatus;"
						+ "attrName;" + "attrChangeOperation;" + "oldValue;"
						+ "newValue" + "\n");
			}

			catch (IOException e1) {
				utils.print("Error writing to file: " + e1.toString());
			}

			for (Iterator<Account> iterator = accounts.iterator(); iterator
					.hasNext();) {
				Account account = iterator.next();
				AccountMO accountMO = new AccountMO(platform, subject,
						account.getDistinguishedName());
				ServiceMO serviceMO = accountMO.getService();
				PersonMO personMO = accountMO.getOwner();
				AttributeValues attrValues = null;
				try {
					attrValues = accountMO.getData().getAttributes();
				} catch (RemoteException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ApplicationException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				Compliance compliance = new Compliance();
				AttributeChanges attrChanges = new AttributeChanges();

				try {
					compliance = accMgr.checkAccountCompliance(personMO,
							serviceMO, attrValues);
				} catch (AuthorizationException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (RemoteException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ApplicationException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				Collection<AttributeValue> av = null;
				try {
					int complianceVal = compliance.getCompliance();
					complianceStr = null;

					switch (complianceVal) {
					case 1:
						complianceStr = "Compliant";
						break;
					case 2:
						complianceStr = "notAuthorised";
						break;
					case 3:
						complianceStr = "nonCompliant";
						break;

					default:
						complianceStr = "unknown";
						break;
					}

					// System.out.println("---Compliance Properties: " +
					// compliance.getAttributeProperties());
					attrChanges = compliance.getRequiredChanges();
					// utils.print("Changes to account " + account.getUserId() +
					// " on Service" +serviceMO.getData().getName() +"\n");
					userName = account.getUserId();
					serviceName = serviceMO.getData().getName();
					for (Iterator iterator2 = attrChanges.iterator(); iterator2
							.hasNext();) {
						AttributeChangeOperation attrChangeOperation = (AttributeChangeOperation) iterator2
								.next();

						// utils.print("attrChangeOPeration action = " +
						// attrChangeOperation.getAction()+"\n");
						av = attrChangeOperation.getChangeData();
						for (Iterator iterator3 = av.iterator(); iterator3
								.hasNext();) {
							AttributeValue attributeValue = (AttributeValue) iterator3
									.next();
							String newVals = attributeValue.getValueString();
							String attrName = attributeValue.getName();
							String oldVals = "";
							// utils.print(userName + ": attrChangeOperation" +
							// attrChangeOperation.getAction().toString() +
							// " : " +
							// attrChangeOperation.getModificationAction());
							// TODO attrChangeOperation.getModificationAction()
							// ==2
							if (attrChangeOperation.getAction().toString()
									.equals("C")) {
								try {
									oldVals = attrValues.get(attrName)
											.getValueString();

									utils.print(userName
											+ ";"
											+ serviceName
											+ ";"
											+ complianceStr
											+ ";"
											+ attrName
											+ ";"
											+ attrChangeOperation
													.getModificationAction()
											+ ";" + oldVals + ";" + newVals
											+ ";");
									try {
										print.write(userName
												+ ";"
												+ serviceName
												+ ";"
												+ complianceStr
												+ ";"
												+ attrName
												+ ";"
												+ attrChangeOperation
														.getModificationAction()
												+ ";" + oldVals + ";" + newVals
												+ "; \n");
									} catch (IOException e1) {
										utils.print("Error writing to file: "
												+ e1.toString());
									}
								} catch (NullPointerException e) {

								}
							}
							// TODO attrChangeOperation.getModificationAction()
							// ==1
							if (attrChangeOperation.getModificationAction() == 1) {
								try {
									oldVals = "";

									utils.print(userName
											+ ";"
											+ serviceName
											+ ";"
											+ complianceStr
											+ ";"
											+ attrName
											+ ";"
											+ attrChangeOperation
													.getModificationAction()
											+ ";" + oldVals + ";" + newVals
											+ ";");
									try {
										print.write(userName
												+ ";"
												+ serviceName
												+ ";"
												+ complianceStr
												+ ";"
												+ attrName
												+ ";"
												+ attrChangeOperation
														.getModificationAction()
												+ ";" + oldVals + ";" + newVals
												+ "; \n");
									} catch (IOException e1) {
										utils.print("Error writing to file: "
												+ e1.toString());
									}
								} catch (NullPointerException e) {

								}
							}

							if (attrChangeOperation.getAction().toString()
									.equals("D")) {
								try {
									oldVals = "";
									// if operation is Delete newVals contains
									// the value to be removed
									utils.print(userName
											+ ";"
											+ serviceName
											+ ";"
											+ complianceStr
											+ ";"
											+ attrName
											+ ";"
											+ attrChangeOperation
													.getModificationAction()
											+ ";" +

											newVals + ";" + oldVals + ";");
									try {

										print.write(userName
												+ ";"
												+ serviceName
												+ ";"
												+ complianceStr
												+ ";"
												+ attrName
												+ ";"
												+ attrChangeOperation
														.getModificationAction()
												+ ";" +

												newVals + ";" + oldVals
												+ "; \n");
									} catch (IOException e1) {
										utils.print("Error writing to file: "
												+ e1.toString());
									}
								} catch (NullPointerException e) {

								}
							}

						}

					}
				} catch (NullPointerException e) {
					utils.print(userName + ";" + serviceName + ";"
							+ complianceStr + ";");

					try {
						print.write(userName + ";" + serviceName + ";"
								+ complianceStr + "; \n");
					} catch (IOException e1) {
						utils.print("Error writing to file: " + e1.toString());
					}
				}

			}
			// Account account = (Account) accounts.iterator().next();

			// utils.print("Request submitted. Process Id: " + request.getID());

		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (LoginException e) {
			e.printStackTrace();
		} catch (SchemaViolationException e) {
			e.printStackTrace();
		} catch (AuthorizationException e) {
			e.printStackTrace();
		} catch (ApplicationException e) {
			e.printStackTrace();
		} finally {
			try {
				print.close();
			} catch (IOException e) {
				utils.print("Error closing file " + e.toString());
			}

			if (platform != null) {

				platform.close();
				platform = null;
			}
		}

		return true;
	}

	public static String getUsage(String msg) {
		StringBuffer usage = new StringBuffer();
		usage.append("\nchangeAccount: " + msg + "\n");
		usage.append("usage: changeAccount -[argument] ? \"[value]\"\n");
		usage.append("\n");
		usage.append("-profile\tObject Profile Name for the Account to change");
		usage.append(" (e.g., LDAPAccount)\n");
		usage.append("-accountfilter\tLdap Filter to search for the Account ");
		usage.append("to change\n");
		usage.append("-filepath\tOutputfile path\n");
		usage.append("\n");
		usage.append("Example: checkPolicy -profile?LDAPAccount ");
		usage.append("-accountfilter?\"(&(owner=*)(eruid=JSmith))\" ");
		usage.append("-attribute?\"filepath=/tmp/checkCompliance.log\" ");

		return usage.toString();
	}

}
