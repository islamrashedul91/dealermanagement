package com.rashed.pharmacy.controller;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.zxing.WriterException;
import com.rashed.pharmacy.model.ProfitLoss;
import com.rashed.pharmacy.dao.ProfitLossDAO;
import com.rashed.pharmacy.util.*;

public class ProfitLossController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	//private static String INSERT_OR_EDIT = "/jsp/account/dayWiseAccountBalanceAdd.jsp";
	private static String LIST_PROFITLOSS = "/jsp/account/profitLossList.jsp";
	private static String ENQUIRY = "/jsp/account/profitLossEnquiry.jsp";
	private ProfitLossDAO dao;
	
	String action = "";
	String message = "";
	
       
    public ProfitLossController() {
        super();
        dao = new ProfitLossDAO();
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
			String profit_loss_id = request.getParameter("profit_loss_id");
			dao.delete(profit_loss_id);
			forward=LIST_PROFITLOSS;
			request.setAttribute("profitLosss", dao.getAllProfitLoss());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("profitLossList")){
			forward = LIST_PROFITLOSS;
			request.setAttribute("profitLosss", dao.getAllProfitLoss());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String profit_loss_id = request.getParameter("profit_loss_id");
			ProfitLoss pl = dao.getProfitLossById(profit_loss_id);
			request.setAttribute("profitLoss", pl);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

}
