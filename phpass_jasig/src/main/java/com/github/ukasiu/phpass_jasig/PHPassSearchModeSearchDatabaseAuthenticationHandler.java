package com.github.ukasiu.phpass_jasig;

import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import com.github.ukasiu.phpass.PHPass;
import org.springframework.beans.factory.InitializingBean;
import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import java.util.Collections;
import java.util.Map;
/**
 * Class that given a table, username field and password field will query a
 * database table to see if the user exists. If the user exists, the
 * encrypted password, from the datbase, will be compared to the plain
 * text password, from the credentials, by using the BCrypt tools.
 */
public class PHPassSearchModeSearchDatabaseAuthenticationHandler extends
    AbstractJdbcUsernamePasswordAuthenticationHandler implements InitializingBean  {
 
  private String fieldUser;
 
  private String fieldPassword;
 
  private String tableUsers;
 
  private String sql;

  private PHPass phpass = new PHPass(20);
 
  public boolean authenticateUsernamePasswordInternal(UsernamePasswordCredentials credentials)  {
    final String username = getPrincipalNameTransformer().transform(credentials.getUsername());
    final String plainTextPassword = credentials.getPassword();
 		
    final String encryptedPassword = getJdbcTemplate().queryForObject(sql, String.class, 
    	(Map<String,String>)Collections.singletonMap("username", username));
 
    return isPasswordValid(plainTextPassword, encryptedPassword);
  }
 
  public void afterPropertiesSet() throws Exception {
    sql = "select " + fieldPassword + " from " +
      tableUsers + " where " + fieldUser + " = :username";
  }
 
  private boolean isPasswordValid(String plainTextPassword, String encryptedPassword) {
    if(plainTextPassword == null || plainTextPassword.trim().length() == 0 ||
        encryptedPassword == null || encryptedPassword.trim().length() == 0) {
      return false;
    }
 
    return phpass.CheckPassword(plainTextPassword, encryptedPassword);
  }
 
  /**
   * @param fieldPassword The name of the encrypted password field.
   */
  public final void setFieldPassword(final String fieldPassword) {
      this.fieldPassword = fieldPassword;
  }
 
  /**
   * @param fieldUser The name of the username field.
   */
  public final void setFieldUser(final String fieldUser) {
      this.fieldUser = fieldUser;
  }
 
  /**
   * @param tableUsers The name of the table holding the user information.
   */
  public final void setTableUsers(final String tableUsers) {
      this.tableUsers = tableUsers;
  }
}