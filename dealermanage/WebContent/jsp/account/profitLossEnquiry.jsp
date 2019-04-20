<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
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
					<li class="title"><a href="">Profit Loss Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Account 
							Management > Profit Loss List > Profit Loss Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Profit Loss ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.profit_loss_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Sales ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.sales_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">From Account ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.from_account_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">To Account ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.to_account_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Total Sales Amount</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.total_sales_amount}" /></td>			
				<td Class ="FormCellColor" colspan="2">Total TP PRICE</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.total_tp_price}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Profit Amount</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.profit_amount}" /></td>
				<td Class ="FormCellColor" colspan="2">Profit Percent</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.profit_percent}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Loss Amount</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.loss_amount}" /></td>
				<td Class ="FormCellColor" colspan="2">Loss percent</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.loss_percent}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.created}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${profitLoss.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.updated}" /></td> --%>
				<td Class ="FormInputColor" colspan="2">
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${profitLoss.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
				</td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${profitLoss.updated_by}" /></td>
			</tr>
			
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/account/profitLoss.jsp">Return</a>
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