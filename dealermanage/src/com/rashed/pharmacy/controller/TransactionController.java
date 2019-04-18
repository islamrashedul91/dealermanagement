package com.rashed.pharmacy.controller;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.zxing.WriterException;

import com.rashed.pharmacy.model.Transaction;
import com.rashed.pharmacy.dao.TransactionDAO;
import com.rashed.pharmacy.util.*;

public class TransactionController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String LIST_TRANSACTION = "/jsp/order/transactionList.jsp";
	private static String ENQUIRY = "/jsp/order/transactionEnquiry.jsp";
	private TransactionDAO dao;
	
	String action = "";
	String message = "";
	
       
    public TransactionController() {
        super();
        dao = new TransactionDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String transaction_id = request.getParameter("transaction_id");
			dao.delete(transaction_id);
			forward=LIST_TRANSACTION;
			request.setAttribute("transactions", dao.getAllTransaction());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("transactionList")){
			forward = LIST_TRANSACTION;
			request.setAttribute("transactions", dao.getAllTransaction());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String transaction_id = request.getParameter("transaction_id");
			Transaction t = dao.getTransactionById(transaction_id);
			request.setAttribute("transaction", t);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

}
