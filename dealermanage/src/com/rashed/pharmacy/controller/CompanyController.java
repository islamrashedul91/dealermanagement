package com.rashed.pharmacy.controller;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.zxing.WriterException;

import com.rashed.pharmacy.model.Company;
import com.rashed.pharmacy.dao.CompanyDAO;
import com.rashed.pharmacy.util.*;

public class CompanyController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/product/companyAdd.jsp";
	private static String LIST_COMPANY = "/jsp/product/companyList.jsp";
	private static String ENQUIRY = "/jsp/product/companyEnquiry.jsp";
	private CompanyDAO dao;
	
	String action = "";
	String message = "";
	
       
    public CompanyController() {
        super();
        dao = new CompanyDAO();
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
			String company_id = request.getParameter("company_id");
			dao.delete(company_id);
			forward=LIST_COMPANY;
			request.setAttribute("companys", dao.getAllCompany());
			message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String company_id = request.getParameter("company_id");
			Company c = dao.getCompanyById(company_id);
			request.setAttribute("company", c);
		} else if(action.equalsIgnoreCase("companyList")){
			forward = LIST_COMPANY;
			request.setAttribute("companys", dao.getAllCompany());
		}  else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String company_id = request.getParameter("company_id");
			Company c = dao.getCompanyById(company_id);
			request.setAttribute("company", c);
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("companyId", dao.getCompanyID().getCompany_id());
			// generated auto increment id during add [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		Company c = new Company();
		
		c.setCompany_id(request.getParameter("company_id"));
		c.setCompany_name(request.getParameter("company_name"));
		c.setDescription(request.getParameter("description"));
		c.setCreated(request.getParameter("created"));
		c.setUpdated(request.getParameter("updated"));
		
		String company_id = request.getParameter("company_id");
		
		if(action.equalsIgnoreCase("save")){
			dao.save(c);
		} else if(action.equalsIgnoreCase("edit")){
			c.setCompany_id(company_id);
			dao.update(c);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_COMPANY);
		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		request.setAttribute("companys", dao.getAllCompany());
		
		rd.forward(request, response);
	}

}