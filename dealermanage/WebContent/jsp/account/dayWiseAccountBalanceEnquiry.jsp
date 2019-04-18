<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<!DOCTYPE html>
<html>
<head>
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

		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Day Wis Account Balance Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Account 
							Management > Day Wis Account Balance List > Day Wis Account Balance Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Day Wis Account Balance ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.day_wise_balance_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Date Time</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.date_time}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Account ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.account_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Account Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.account_type}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Account Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.account_name}" /></td>			
				<td Class ="FormCellColor" colspan="2">Description</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.description}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Previous Balance</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.previous_balance}" /></td>
				<td Class ="FormCellColor" colspan="2">Credit Balance</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.credit_balance}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Debit Balance</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.debit_balance}" /></td>
				<td Class ="FormCellColor" colspan="2">Current Balance</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.current_balance}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Day Balance</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.day_balance}" /></td>
				<td Class ="FormCellColor" colspan="2"></td>
				<td Class ="FormInputColor" colspan="2"></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.created}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${dayWiseAccountBalance.updated}" /></td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/account/dayWiseAccountBalance.jsp">Return</a>
					</td>
				</tr>
		</table>
	</form>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>