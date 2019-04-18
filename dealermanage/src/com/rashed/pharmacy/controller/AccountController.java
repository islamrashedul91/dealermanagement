package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.Account;
import com.rashed.pharmacy.dao.AccountDAO;
import com.rashed.pharmacy.util.*;

public class AccountController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/account/accountAdd.jsp";
	private static String LIST_ACCOUNT = "/jsp/account/accountList.jsp";
	private static String ENQUIRY = "/jsp/account/accountEnquiry.jsp";
	private AccountDAO dao;
	
	String action = "";
	String message = "";
	
       
    public AccountController() {
        super();
        dao = new AccountDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			//int id=Integer.parseInt(request.getParameter("id"));
			String account_id = request.getParameter("account_id");
			dao.delete(account_id);
			forward=LIST_ACCOUNT;
			request.setAttribute("accounts", dao.getAllAccount());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String account_id = request.getParameter("account_id");
			Account a = dao.getAccountById(account_id);
			request.setAttribute("account", a);
		} else if(action.equalsIgnoreCase("accountList")){
			forward = LIST_ACCOUNT;
			request.setAttribute("accounts", dao.getAllAccount());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String account_id = request.getParameter("account_id");
			Account a = dao.getAccountById(account_id);
			request.setAttribute("account", a);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("accountId", dao.getAccountID().getAccount_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		Account a = new Account();
		
		a.setAccount_id(request.getParameter("account_id"));
		a.setAccount_type(request.getParameter("account_type"));
		a.setAccount_name(request.getParameter("account_name"));
		a.setDescription(request.getParameter("description"));
		a.setPrevious_balance(Double.parseDouble(request.getParameter("previous_balance")));
		a.setCurrent_balance(Double.parseDouble(request.getParameter("current_balance")));
		a.setCreated(request.getParameter("created"));
		a.setUpdated(request.getParameter("updated"));
		
		String account_id = request.getParameter("account_id");
		
		if(action.equalsIgnoreCase("save")){
			dao.save(a);
		} else if(action.equalsIgnoreCase("edit")){
			a.setAccount_id(account_id);
			dao.update(a);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_ACCOUNT);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("accounts", dao.getAllAccount());
		
		rd.forward(request, response);
	}

}
