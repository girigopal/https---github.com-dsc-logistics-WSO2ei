/*
*  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing,
*  software distributed under the License is distributed on an
*  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
*  KIND, either express or implied.  See the License for the
*  specific language governing permissions and limitations
*  under the License.
*/
package org.demo;

import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import java.util.Hashtable;
import java.util.Random;

import javax.naming.AuthenticationException;
import javax.naming.AuthenticationNotSupportedException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import org.json.JSONObject;

public class AuthenticateUserMediator extends AbstractMediator {

    @Override
    public boolean mediate(MessageContext context) {
        try {
            String payload = onCall(context);
            org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) context)
                    .getAxis2MessageContext();
            JsonUtil.getNewJsonPayload(axis2MessageContext, payload, true, true);
        } catch (Exception e) {
            handleException("Error", e, context);
        }
        return true;
    }

    public String onCall(MessageContext context) throws Exception {
        JSONObject inputJsonObj;
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) context)
                .getAxis2MessageContext();
        inputJsonObj = new JSONObject(JsonUtil.jsonPayloadToString(axis2MessageContext));

        String str = JsonUtil.jsonPayloadToString(((Axis2MessageContext) context).getAxis2MessageContext())
                + " this is get message getpayload";
        //  str=inputJsonObj.get("name").toString();

        StringBuffer sb = new StringBuffer();
        String msg;
        String err;
        String username = "";
        String password = "";

        if ((inputJsonObj.has("username")) && (inputJsonObj.has("password"))) {
            msg = "{}";
        } else {
            err = "Json elements username and password is required for this API ";
            sb.append("{\"result\":\"FAILED\",\"resultCode\":300,\"message\":\"" + err + "\"}");
            return sb.toString();
        }

        if ((inputJsonObj.get("username").toString().length() > 0) && (inputJsonObj.get("password").toString().length()
                > 0)) {
            username = inputJsonObj.get("username").toString().toLowerCase();
            password = inputJsonObj.get("password").toString();
            msg = authenticateUser(username, password, sb);
        } else  {
            err = "Json elements username and/or password is empty. Please try with valid user/password for this API ";
            sb.append("{\"result\":\"FAILED\",\"resultCode\":300,\"message\":\"" + err + "\"}");
            msg = sb.toString();
        }
        //    System.out.println (" after ldap dsc msg is:"+msg);
        // failed then verify agains colonical heights domain
        if (msg.toLowerCase().contains("failed")) {
            msg = authenticateUserCH(username, password, sb);
        }
        // if both domain failes see if the user is in LDAP domains if not then
        // verify agains user tables
        JSONObject js = new JSONObject(msg);
        String fnduser = "";
        if (msg.toLowerCase().contains("failed")) {

            System.out.println("Authentication Failed");
            LdapContext ldapContextdsc = getDSCLdapContext();
            LdapContext ldapContextch = getCHLdapContext();
            SearchControls searchControls = getSearchControls();
            String suser = username;
            fnduser = getUserInfo(suser, ldapContextdsc, searchControls, "DSCLogistics");
            int authsys = 0;
            if (fnduser.equals("Y")) {
                String hmsg = getSchema(username);
                authsys = 1;
                System.out.println("${suser} User Found in LDAP");
                js.remove("message");
                js.put("message", "Invalid Password");
                JSONObject jsx = new JSONObject(hmsg);
                js.put("userRouting", jsx);

            } else {

                fnduser = getUserInfo(suser, ldapContextch, searchControls, "Colonial Heights");
                if (fnduser.equals("Y")) {
                    String hmsg = getSchema(username);
                    authsys = 2;
                    System.out.println("${suser} User   Found in CH CH LDAP");
                    js.remove("message");
                    js.put("message", "Invalid Password");
                    JSONObject jsx = new JSONObject(hmsg);
                    js.put("userRouting", jsx);
                } else {
                    js.remove("message");
                    js.put("message", "Invalid User");
                }
            }

        }
        msg = js.toString();

        // if the user is still invalid check if the password and user
        // matches to user table for temp employees
        if (msg.toLowerCase().contains("failed") && fnduser.equals("N")) {
            msg = verifyUser(username, password, msg);

        }

        // Before returning see if you have user routing
        try {
            String appuid = "";
            JSONObject ipinfo = new JSONObject(msg);
            if (ipinfo.has("appuserid")) {
                System.out.println(" Found appuser ***");
            }
            if (ipinfo.has("userid")) {
                System.out.println(" Found userid ####");
            }

            if (ipinfo.has("userRouting")) {
                JSONObject routing = ipinfo.getJSONObject("userRouting");
                String appid = routing.getString("userid");
                System.out.println(" Found UserRouting JSON OBJECT");

                if (ipinfo.has("DSCAuthenticationSrv")) {
                    JSONObject routinga = ipinfo.getJSONObject("DSCAuthenticationSrv");
                    String appido = routinga.getString("appuserid");
                    routinga.remove("appuserid");
                    routinga.accumulate("appuserid", appid);
                    ipinfo.remove("DSCAuthenticationSrv");
                    ipinfo.accumulate("DSCAuthenticationSrv", routinga);
                    // ipinfo.append("DSCAuthenticationSrv",routinga);
                    System.out.println(" Found DSCAuthenticationSrv JSON OBJECT");
                    msg = ipinfo.toString();
                } else {
                    msg = verifyUser(username, password, msg);    // remove else

                }
            }

        } catch (Exception jerr) {
            //ignore
        }

        System.out.println(" FINAL PAYLOAD:" + msg);
        return msg;
    }

    // COlonial Heights Domain
    public String authenticateUserCH(String username, String password, StringBuffer sb) {
        String msg = "";
        String err = "";
        //String url = "ldap://192.168.2.1/OU=Desktop,OU=User Accounts,OU=CORPORATE HEADQUARTERS\\, IL,DC=dsclogistics,DC=dsccorp,DC=net";
        String url = "ldap://192.168.99.25/DC=ColonialHeights,DC=DSCCORP,DC=net";
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, new String("dsclogistics" + "\\" + username));
        env.put(Context.SECURITY_CREDENTIALS, password);

        DirContext ctx = null;
        NamingEnumeration results = null;

        try {
            ctx = new InitialDirContext(env);
//            rb = Response.ok(ctx.getEnvironment().toString()).build();
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String[] attrIDs = {
                    "distinguishedName", "sn", "givenname", "mail", "sAMAccountName", "objectclass", "telephonenumber"
            };
            controls.setReturningAttributes(attrIDs);
            //  results = ctx.search("", "(objectclass=person)", controls);
            results = ctx.search("", "(sAMAccountName=" + username + ")", controls);

            if (results.hasMore()) {
                Attributes attrs = ((SearchResult) results.next()).getAttributes();
                //	System.out.println("distinguishedName "+ attrs.get("distinguishedName"));
                String[] dname = attrs.get("distinguishedName").toString().split(",");
                String[] cnname = dname[0].split("=");
                String fld = null;
                fld = attrs.get("givenname").toString();
                String[] parts = fld.split(":");

                String fname = parts[1].trim();
                fld = attrs.get("sn").toString();
                parts = fld.split(":");
                String lname = parts[1].trim();
                fld = attrs.get("mail").toString();
                parts = fld.split(" ");
                String email = parts[1].trim();
                msg = ",\"DSCAuthenticationSrv\":";
                msg = msg + "{\"name\":\"" + cnname[1] + "\",\"first_name\":\"" + fname + "\",\"last_name\":\"" + lname
                        + "\",\"email\":\"" + email + "\"}";
                Random rand = new Random();
                int rndvalue = rand.nextInt(50);
                msg = ",\"DSCAuthenticationSrv\":";
                msg = msg + "{\"appuserid\":" + rndvalue + ",";
                msg = msg + "\"name\":\"" + cnname[1] + "\",\"first_name\":\"" + fname + "\",\"last_name\":\"" + lname
                        + "\",\"email\":\"" + email + "\"}";

                String hmsg = getSchema(username);
                System.out.println("The authentication get message is:" + hmsg);
                if (hmsg.length() > 10) {
                    //  sb.append("{\"result\":\"SUCCESS\",\"resultCode\":0,\"message\":\"\""+msg+"}");
                    sb.append("{\"result\":\"SUCCESS\",\"resultCode\":0,\"message\":\"\"" + msg + ",\"userRouting\":"
                            + hmsg + "}");
                } else {
                    sb.append("{\"result\":\"SUCCESS\",\"resultCode\":0,\"message\":\"\"" + msg + "}");
                }
                // sb.append("{\"result\":\"SUCCESS\",\"resultCode\":0,\"message\":\"\""+msg+",\"userRouting\":"+hmsg+"}");

            }

            ctx.close();

        } catch (AuthenticationNotSupportedException ex) {
            //	System.out.println("The authentication is not supported by the server");
            err = "The authentication is not supported by the server";
            // sb.append("{\"result\":\"FAILED\",\"resultCode\":300,\"message\":\"" +msg +"\"}");
        } catch (AuthenticationException ex) {
            err = err + "incorrect password or username";
            // sb.append("{\"result\":\"FAILED\",\"resultCode\":300,\"message\":\"" +msg +"\"}");
            //	System.out.println("incorrect password or username");
        } catch (NamingException ex) {
            err = err + "error when trying to create the context";
            //sb.append("{\"result\":\"FAILED\",\"resultCode\":300,\"message\":\"" +msg +"\"}");
            //	System.out.println("error when trying to create the context"+ex.getMessage().toString());
        } catch (Exception ex) {
            // System.out.println("Error Getting Attrs:"+ex.getMessage().toString());
            err = err + "Error Getting Attrs";

        }
        if (err.length() > 0) {
            sb.append("{\"result\":\"FAILED\",\"resultCode\":300,\"message\":\"" + err + "\"}");
        }

        return sb.toString();
    }

    // DSC Logistics Domain

    public String authenticateUser(String username, String password, StringBuffer sb) {
        String msg = "";
        String err = "";
        //String url = "ldap://192.168.2.1/OU=Desktop,OU=User Accounts,OU=CORPORATE HEADQUARTERS\\, IL,DC=dsclogistics,DC=dsccorp,DC=net";
        String url = "ldap://192.168.2.1/DC=dsclogistics,DC=dsccorp,DC=net";
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, new String("dsclogistics" + "\\" + username));
        env.put(Context.SECURITY_CREDENTIALS, password);

        DirContext ctx = null;
        NamingEnumeration results = null;

        try {
            ctx = new InitialDirContext(env);
//            rb = Response.ok(ctx.getEnvironment().toString()).build();
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String[] attrIDs = {
                    "distinguishedName", "sn", "givenname", "mail", "sAMAccountName", "objectclass", "telephonenumber"
            };
            controls.setReturningAttributes(attrIDs);
            //  results = ctx.search("", "(objectclass=person)", controls);
            results = ctx.search("", "(sAMAccountName=" + username + ")", controls);

            if (results.hasMore()) {
                Attributes attrs = ((SearchResult) results.next()).getAttributes();
                //	System.out.println("distinguishedName "+ attrs.get("distinguishedName"));
                String[] dname = attrs.get("distinguishedName").toString().split(",");
                String[] cnname = dname[0].split("=");
                String fld = null;
                fld = attrs.get("givenname").toString();
                String[] parts = fld.split(":");

                String fname = parts[1].trim();
                fld = attrs.get("sn").toString();
                parts = fld.split(":");
                String lname = parts[1].trim();
                fld = attrs.get("mail").toString();
                parts = fld.split(" ");
                String email = parts[1].trim();
                msg = ",\"DSCAuthenticationSrv\":";
                msg = msg + "{\"name\":\"" + cnname[1] + "\",\"first_name\":\"" + fname + "\",\"last_name\":\"" + lname
                        + "\",\"email\":\"" + email + "\"}";
                Random rand = new Random();
                int rndvalue = rand.nextInt(50);
                msg = ",\"DSCAuthenticationSrv\":";
                msg = msg + "{\"appuserid\":" + rndvalue + ",";
                msg = msg + "\"name\":\"" + cnname[1] + "\",\"first_name\":\"" + fname + "\",\"last_name\":\"" + lname
                        + "\",\"email\":\"" + email + "\"}";

                String hmsg = getSchema(username);
                System.out.println("The authentication get message is:" + hmsg);
                if (hmsg.length() > 10) {
                    //  sb.append("{\"result\":\"SUCCESS\",\"resultCode\":0,\"message\":\"\""+msg+"}");
                    sb.append("{\"result\":\"SUCCESS\",\"resultCode\":0,\"message\":\"\"" + msg + ",\"userRouting\":"
                            + hmsg + "}");
                } else {
                    sb.append("{\"result\":\"SUCCESS\",\"resultCode\":0,\"message\":\"\"" + msg + "}");
                }
            }

            ctx.close();

        } catch (AuthenticationNotSupportedException ex) {
            //	System.out.println("The authentication is not supported by the server");
            err = "The authentication is not supported by the server";
            // sb.append("{\"result\":\"FAILED\",\"resultCode\":300,\"message\":\"" +msg +"\"}");
        } catch (AuthenticationException ex) {
            err = err + "incorrect password or username";
            // sb.append("{\"result\":\"FAILED\",\"resultCode\":300,\"message\":\"" +msg +"\"}");
            //	System.out.println("incorrect password or username");
        } catch (NamingException ex) {
            err = err + "error when trying to create the context";
            //sb.append("{\"result\":\"FAILED\",\"resultCode\":300,\"message\":\"" +msg +"\"}");
            //	System.out.println("error when trying to create the context"+ex.getMessage().toString());
        } catch (Exception ex) {
            // System.out.println("Error Getting Attrs:"+ex.getMessage().toString());
            err = err + "Error Getting Attrs";

        }
        if (err.length() > 0) {
            sb.append("{\"result\":\"FAILED\",\"resultCode\":300,\"message\":\"" + err + "\"}");
        }
        return sb.toString();
    }

    // verify if user is in usertable verify password with clock number
    public String verifyUser(String username, String password, String msg) {
        try {
            Connection c = null;
            Statement stmt = null;
            String yn = "N";
            String hmsg = "";
            String ymsg = "";
            JSONObject js = new JSONObject(msg);

            try {
                Class.forName("org.postgresql.Driver");
                //	        c = DriverManager.getConnection("jdbc:postgresql://172.31.49.181:5432/DSC_APPS","postgres", "postgres"); // QA
                c = DriverManager
                        .getConnection("jdbc:postgresql://172.31.62.43:5432/DSC_APPS", "postgres", "postgres"); // PROD

                stmt = c.createStatement();
                String selsql = " select b.src_sys_id,b.lc_id,a.user_id,b.target_url,d.hostname, "
                        + " a.full_name, a.email_addr  from md_schema.app_user  as a "
                        + " inner join md_schema.user_routing as b on a.user_id = b.user_id "
                        + " inner join md_schema.lc as c on b.lc_id = c.lc_id "
                        + " inner join md_schema.src_sys as d on b.src_sys_id= d.src_sys_id "
                        + " where LOWER(a.username)='" + username + "' and emp_id='" + password + "'";
                System.out.println(" sql query is:" + selsql);
                // ResultSet rs = stmt.executeQuery( "SELECT * FROM md_schema.src_sys;" );
                ResultSet rs = stmt.executeQuery(selsql);
                String fullname = "";
                String email = "";
                String fname = "";
                String lname = "";

                while (rs.next()) {
                    yn = "Y";
                    // String  address = rs.getString("address");
                    // float salary = rs.getFloat("salary");
                    System.out.print("SRCSYSID = " + rs.getString(1));
                    System.out.print("lcid = " + rs.getString(2));
                    System.out.print("userid = " + rs.getString(3));
                    System.out.print("targeturl = " + rs.getString(4));
                    System.out.print("Host = " + rs.getString(5));
                    System.out.println();
                    hmsg = "{\"srcsysid\":\"" + rs.getString(1) + "\",";
                    hmsg = hmsg + "\"lcid\":\"" + rs.getString(2) + "\",";
                    hmsg = hmsg + "\"userid\":\"" + rs.getString(3) + "\",";
                    hmsg = hmsg + "\"targeturl\":\"" + rs.getString(4) + "\",";
                    hmsg = hmsg + "\"host\":\"" + rs.getString(5) + "\"}";
                    fullname = rs.getString(6);
                    email = rs.getString(7);
                    String[] nparts = fullname.split(",");
                    if (nparts.length >= 2) {
                        String[] fm = nparts[1].split(" ");
                        fname = fm[0];
                    }
                    // if (nparts.length >= 2) fname=nparts[1].split(" ");
                    if (nparts.length >= 1)
                        lname = nparts[0];

                    ymsg = "{\"name\": \"" + fullname + "\"," + "\"first_name\": \"" + fname + "\","
                            + "\"last_name\": \"" + lname + "\"," + "\"email\": \"" + email + "\","
                            + "\"appuserid\": \"" + rs.getString(3) + "\"}}";
                    System.out.println(" add ing authenication now:" + hmsg);
                }
                rs.close();
                stmt.close();
                c.close();
            } catch (Exception e) {
                // e.printStackTrace();
                System.out.println(" Error :" + e.getClass().getName() + ": " + e.getMessage());
                // System.exit(0);
            }
            System.out.println("Opened database successfully");
            if (yn.equals("Y")) {
                js.remove("message");
                js.put("message", "");
                js.remove("result");
                js.put("result", "SUCCESS");
                js.remove("resultCode");
                js.put("resultCode", 0);
                JSONObject jsx = new JSONObject(hmsg);
                JSONObject jsx2 = new JSONObject(ymsg);
                if (hmsg.length() > 10) {
                    js.put("userRouting", jsx);
                    js.put("DSCAuthenticationSrv", jsx2);
                }

                msg = js.toString();

            }
            // return "Hello " +username;
            // return msg;

        } catch (Exception e) {

        }
        return msg;
    }

    public String getSchema(String username) {
        Connection c = null;
        Statement stmt = null;
        String msg = "";
        try {
            Class.forName("org.postgresql.Driver");
            //       c = DriverManager.getConnection("jdbc:postgresql://172.31.49.181:5432/DSC_APPS","postgres", "postgres"); // QA
            c = DriverManager
                    .getConnection("jdbc:postgresql://172.31.62.43:5432/DSC_APPS", "postgres", "postgres"); // PROD

            stmt = c.createStatement();
            String selsql =
                    " select b.src_sys_id,b.lc_id,b.user_id,b.target_url,d.hostname  from md_schema.app_user  as a "
                            + " inner join md_schema.user_routing as b on a.user_id = b.user_id "
                            + " inner join md_schema.lc as c on b.lc_id = c.lc_id "
                            + " inner join md_schema.src_sys as d on b.src_sys_id= d.src_sys_id "
                            + " where LOWER(a.username)='" + username + "'";
            System.out.println(" sql query is:" + selsql);
            // ResultSet rs = stmt.executeQuery( "SELECT * FROM md_schema.src_sys;" );
            ResultSet rs = stmt.executeQuery(selsql);
            while (rs.next()) {

                // String  address = rs.getString("address");
                // float salary = rs.getFloat("salary");
                System.out.print("SRCSYSID = " + rs.getString(1));
                System.out.print("lcid = " + rs.getString(2));
                System.out.print("userid = " + rs.getString(3));
                System.out.print("targeturl = " + rs.getString(4));
                System.out.print("Host = " + rs.getString(5));
                System.out.println();
                msg = "{\"srcsysid\":\"" + rs.getString(1) + "\",";
                msg = msg + "\"lcid\":\"" + rs.getString(2) + "\",";
                msg = msg + "\"userid\":\"" + rs.getString(3) + "\",";
                msg = msg + "\"targeturl\":\"" + rs.getString(4) + "\",";
                msg = msg + "\"host\":\"" + rs.getString(5) + "\"}";

            }
            rs.close();
            stmt.close();
            c.close();
        } catch (Exception e) {
            // e.printStackTrace();
            System.out.println(" Error :" + e.getClass().getName() + ": " + e.getMessage());
            // System.exit(0);
        }
        System.out.println("Opened database successfully");

        return msg;
    }

    private static LdapContext getDSCLdapContext() {
        LdapContext ctx = null;
        try {

            // ========================================================================================================
            // dc=colonialhights  forest=dc=dsccorp dsc=net  domain for colonialheights = 192.168.99.25

            String password = "Apps@dsc2";
            String username = "User_Apps";
            String url = "ldap://192.168.2.1/DC=dsclogistics,DC=dsccorp,DC=net";
            //String url="ldap://192.168.43.36/DC=dsccorp,DC=net";
            Hashtable env = new Hashtable();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, url);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, new String("dsclogistics" + "\\" + username));
            env.put(Context.SECURITY_CREDENTIALS, password);
            ctx = new InitialLdapContext(env, null);
            System.out.println("DSCLogistiacs LDAP Connection: COMPLETE");

        } catch (NamingException nex) {
            System.out.println("LDAP Connection: FAILED");
            nex.printStackTrace();
        }
        return ctx;
    }

    private static LdapContext getCHLdapContext() {
        LdapContext ctx = null;
        try {

            // ========================================================================================================
            // dc=colonialhights  forest=dc=dsccorp dsc=net  domain for colonialheights = 192.168.99.25

            String password = "M0c049kDn%XEZBc0J%n1";
            String username = "User_Apps";
            String url = "ldap://192.168.99.25/DC=ColonialHeights,DC=DSCCORP,DC=net";
            //String url="ldap://192.168.43.36/DC=dsccorp,DC=net";
            Hashtable env = new Hashtable();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, url);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, new String("colonialheights" + "\\" + username));
            env.put(Context.SECURITY_CREDENTIALS, password);
            ctx = new InitialLdapContext(env, null);
            System.out.println("CH LDAP Connection: COMPLETE");

        } catch (NamingException nex) {
            System.out.println("CH LDAP Connection: FAILED");
            nex.printStackTrace();
        }
        return ctx;
    }

    private static String getUserInfo(String userName, LdapContext ctx, SearchControls searchControls, String dname) {
        System.out.println("*** " + userName + " ***");
        String yn = "N";
        // User user = null;
        try {
            //  NamingEnumeration<SearchResult> answer = ctx.search("dc=epam,dc=com", "sAMAccountName=" + userName, searchControls);
            NamingEnumeration<SearchResult> answer = ctx.search("", "sAMAccountName=" + userName, searchControls);
            if (answer.hasMore()) {
                Attributes attrs = answer.next().getAttributes();
                yn = "Y";
                //  byte[] photo = (byte[])attrs.get("thumbnailPhoto").get();
                //   savePhoto(userName, photo);
            } else {
                System.out.println(" ####### " + dname + "  user not found.########");
            }
        } catch (Exception ex) {
            System.out.println(" ####### " + dname + "  user not found.########");
            // ex.printStackTrace();
        }
        // return user;
        return yn;
    }

    private static SearchControls getSearchControls() {
        SearchControls cons = new SearchControls();
        cons.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String[] attrIDs = { "distinguishedName", "sn", "givenname", "mail", "telephonenumber", "thumbnailPhoto" };
        // String [] attrIDs ={"givenname"};
        cons.setReturningAttributes(attrIDs);
        return cons;
    }

}
