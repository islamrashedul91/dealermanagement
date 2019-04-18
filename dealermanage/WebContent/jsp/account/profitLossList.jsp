<jsp:include page="base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<!-- <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1"> -->
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/copytest.css" />
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/table.css" />

<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/jquery.min.js"></script>
<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/dataTables/jquery.dataTables.min.js"></script>
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/jquery.dataTables.min.css">
	
<title>onlinep</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script type="text/javascript">

$(document).ready(function() {
	$('#example').DataTable();
});

function getRadioValue()
{
	var id = document.getElementsByName('profit_loss_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	//var updatePathWithIdValue = "${pageContext.request.contextPath}/DayWiseAccountBalanceController?action=edit&day_wise_balance_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/ProfitLossController?action=delete&profit_loss_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/ProfitLossController?action=enquiry&profit_loss_id="+idValue;
	//for enquiry [E]
	
	if (idValue !=null) {
		//for update [S]
		//document.getElementById('update').href = updatePathWithIdValue;
		//for update [E]
		//for delete [S]
		document.getElementById('delete').href = deletePathWithIdValue;
		//for delete [E]
		//for enquiry [S]
		document.getElementById('enquiry').href = enquiryPathWithIdValue;
		//for enquiry [E]
	} else {
		alert("Please select a ID!!");
		return false;
	}
}

</script>
</head>
<body>

<%
String message = (String) request.getAttribute("success");
%>
	<table align="center">
				<%
				if(message!=null) {
				%>
				<tr>
					<th Class="HeaderTH"><%=message %></th>
				</tr>
				<%
				}
				%>
	</table>
	<br>
<div class="mcontent">
			<div class="titlenav">
			<ul>
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/account/profitLoss.jsp">Profit Loss List</a></li>
					<li class="bread"><a href="">Dashboard > Account 
							Management > Profit Loss List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<th Class ="HeaderTH">Profit Loss ID</th>
				<th Class ="HeaderTH">Sales ID</th>
				<th Class ="HeaderTH">From Account ID</th>
				<!-- <th Class ="HeaderTH">To Account ID</th> -->
				<th Class ="HeaderTH">Total Sales Amount</th>
				<th Class ="HeaderTH">Total TP PRICE</th>
				<th Class ="HeaderTH">Profit Amount</th>
				<th Class ="HeaderTH">Profit Percent</th>
				<th Class ="HeaderTH">Loss Amount</th>
				<th Class ="HeaderTH">Loss percent</th>
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${profitLosss}" var="pl"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="profit_loss_id" id="profit_loss_id" value="${pl.profit_loss_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${pl.profit_loss_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${pl.sales_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${pl.from_account_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${pl.to_account_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${pl.total_sales_amount}" /></td>
					<td Class ="FormInputColor"><c:out value="${pl.total_tp_price}" /></td>
					<td Class ="FormInputColor"><c:out value="${pl.profit_amount}" /></td>
					<td Class ="FormInputColor"><c:out value="${pl.profit_percent}" /></td>
					<td Class ="FormInputColor"><c:out value="${pl.loss_amount}" /></td>
					<td Class ="FormInputColor"><c:out value="${pl.loss_percent}" /></td>
				</tr>
			</c:forEach>
		</tbody>
	</table>
	<br>
<input type="hidden" name="val" id="val" value="" />
	<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399>
					<br>
					<a id="delete" Class ="button" href="" onclick="javascript: getRadioValue();">delete</a>
					<a id="enquiry" Class ="button" href="" onclick="javascript: getRadioValue();">enquiry</a>
					<a Class ="button" href="${pageContext.request.contextPath}/base.jsp">Return</a></td>
				</tr>
	</table>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>