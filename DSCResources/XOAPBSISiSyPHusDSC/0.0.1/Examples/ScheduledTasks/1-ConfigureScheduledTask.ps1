configuration Example
{
    param
    (
        [string[]]$NodeName = 'localhost'
    )

    Import-DSCResource -ModuleName XOAPModuleTemplateDSC

    WindowsFeature IIS
    {
        Ensure          = "Present"
        Name            = "Web-Server"
    }
}

