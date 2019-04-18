package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.DayWiseAccountBalance;
import com.rashed.pharmacy.dao.DayWiseAccountBalanceDAO;
import com.rashed.pharmacy.util.*;

public class DayWiseAccountBalanceController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/account/dayWiseAccountBalanceAdd.jsp";
	private static String LIST_DAYWISEACCOUNTBALANCE = "/jsp/account/dayWiseAccountBalanceList.jsp";
	private static String ENQUIRY = "/jsp/account/dayWiseAccountBalanceEnquiry.jsp";
	private DayWiseAccountBalanceDAO dao;
	
	String action = "";
	String message = "";
	
       
    public DayWiseAccountBalanceController() {
        super();
        dao = new DayWiseAccountBalanceDAO();
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
			String day_wise_balance_id = request.getParameter("day_wise_balance_id");
			dao.delete(day_wise_balance_id);
			forward=LIST_DAYWISEACCOUNTBALANCE;
			request.setAttribute("dayWiseAccountBalances", dao.getAllDayWiseAccountBalance());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String day_wise_balance_id = request.getParameter("day_wise_balance_id");
			DayWiseAccountBalance dwab = dao.getDayWiseAccountBalanceById(day_wise_balance_id);
			request.setAttribute("dayWiseAccountBalance", dwab);
		} else if(action.equalsIgnoreCase("dayWiseAccountBalanceList")){
			forward = LIST_DAYWISEACCOUNTBALANCE;
			request.setAttribute("dayWiseAccountBalances", dao.getAllDayWiseAccountBalance());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String day_wise_balance_id = request.getParameter("day_wise_balance_id");
			DayWiseAccountBalance dwab = dao.getDayWiseAccountBalanceById(day_wise_balance_id);
			request.setAttribute("dayWiseAccountBalance", dwab);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("dayWiseAccountBalanceId", dao.getDayWiseAccountBalanceID().getDay_wise_balance_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		DayWiseAccountBalance dwab = new DayWiseAccountBalance();
		
		dwab.setDay_wise_balance_id(request.getParameter("day_wise_balance_id"));
		dwab.setDate_time(request.getParameter("date_time"));
		dwab.setAccount_id(request.getParameter("account_id"));
		dwab.setAccount_type(request.getParameter("account_type"));
		dwab.setAccount_name(request.getParameter("account_name"));
		dwab.setDescription(request.getParameter("description"));
		dwab.setPrevious_balance(Double.parseDouble(request.getParameter("previous_balance")));
		dwab.setCredit_balance(Double.parseDouble(request.getParameter("credit_balance")));
		dwab.setDebit_balance(Double.parseDouble(request.getParameter("debit_balance")));
		dwab.setCurrent_balance(Double.parseDouble(request.getParameter("current_balance")));
		dwab.setDay_balance(Double.parseDouble(request.getParameter("day_balance")));
		dwab.setCreated(request.getParameter("created"));
		dwab.setUpdated(request.getParameter("updated"));
		
		String day_wise_balance_id = request.getParameter("day_wise_balance_id");
		
		if(action.equalsIgnoreCase("save")){
			dao.save(dwab);
		} else if(action.equalsIgnoreCase("edit")){
			dwab.setDay_wise_balance_id(day_wise_balance_id);
			//dao.update(dwab);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_DAYWISEACCOUNTBALANCE);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("dayWiseAccountBalances", dao.getAllDayWiseAccountBalance());
		
		rd.forward(request, response);
	}

}
